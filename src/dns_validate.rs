use std::{pin::Pin, time::Duration};

use anyhow::{Context, Result, ensure};
use futures_util::{Stream, StreamExt, stream};
use hickory_net::{DnsHandle, NetError, dnssec::DnssecDnsHandle, runtime::TokioRuntimeProvider};
use hickory_proto::{
    dnssec::{DnssecSummary, Proof},
    op::{DnsRequest, DnsResponse, Message},
};
use tokio::sync::{mpsc, oneshot};

pub struct Request {
    pub query: Message,
    pub reply: oneshot::Sender<Message>,
}

#[derive(Clone)]
pub struct Validator(DnssecDnsHandle<Channel>);

impl Validator {
    pub fn new() -> (Self, mpsc::Receiver<Request>) {
        let (sender, receiver) = mpsc::channel(64);
        (
            Self(
                DnssecDnsHandle::new(Channel(sender))
                    .validation_cache_size(512)
                    .nsec3_iteration_limits(Some(50), Some(100)),
            ),
            receiver,
        )
    }

    pub async fn query(&self, query: Message) -> Result<Message> {
        let mut request = DnsRequest::from(query.clone());
        request.metadata.checking_disabled = false;
        let mut responses = self.0.send(request);
        let response = tokio::time::timeout(Duration::from_secs(12), responses.next())
            .await
            .context("DNSSEC 验证超时")?
            .context("DNSSEC 未返回结果")??;
        let mut response = response.into_message();
        ensure!(
            !response.answers.is_empty() || !response.authorities.is_empty(),
            "DNSSEC 负响应缺少可验证的证明"
        );
        ensure!(
            response
                .answers
                .iter()
                .chain(&response.authorities)
                .all(|record| !matches!(record.proof, Proof::Bogus | Proof::Indeterminate)),
            "DNSSEC 签名或信任链未通过验证"
        );
        // AD 只能由本地密码学验证产生，不能照抄上游声称的“已验证”标志。
        let summary =
            DnssecSummary::from_records(response.answers.iter().chain(&response.authorities));
        ensure!(summary != DnssecSummary::Bogus, "DNSSEC 签名无效");
        response.metadata.authentic_data = summary == DnssecSummary::Secure;
        response.metadata.id = query.metadata.id;
        response.metadata.checking_disabled = false;
        Ok(response)
    }
}

#[derive(Clone)]
struct Channel(mpsc::Sender<Request>);

impl DnsHandle for Channel {
    type Response = Pin<Box<dyn Stream<Item = std::result::Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let sender = self.0.clone();
        Box::pin(stream::once(async move {
            let (mut query, _) = request.into_parts();
            // 向上游索取原始签名材料；即使上游跳过验证，本机仍独立校验完整链。
            query.metadata.checking_disabled = true;
            let (reply, receiver) = oneshot::channel();
            sender
                .try_send(Request { query, reply })
                .map_err(|_| NetError::from("DNSSEC 请求队列已满或退出"))?;
            let response = receiver
                .await
                .map_err(|_| NetError::from("DNSSEC 查询已取消"))?;
            DnsResponse::from_message(response).map_err(NetError::from)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Query, ResponseCode},
        rr::{Name, RData, Record},
    };

    #[tokio::test]
    async fn forged_ad_and_unsigned_empty_proofs_do_not_become_trusted_answers() {
        let (validator, mut requests) = Validator::new();
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("forged.example.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let task = tokio::spawn(async move { validator.query(query).await });
        for _attempt in 0..32 {
            tokio::select! {
                request = requests.recv() => {
                    let Some(request) = request else { break; };
                    assert!(request.query.metadata.checking_disabled);
                    let mut response = crate::dns::reply(&request.query, ResponseCode::NoError);
                    response.metadata.authentic_data = true;
                    if request.query.queries[0].query_type() == hickory_proto::rr::RecordType::A {
                        response.answers.push(Record::from_rdata(request.query.queries[0].name().clone(), 30, RData::from("192.0.2.10".parse::<std::net::IpAddr>().unwrap())));
                    }
                    let _ = request.reply.send(response);
                }
                _ = tokio::time::sleep(Duration::from_millis(10)), if task.is_finished() => break,
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
}
