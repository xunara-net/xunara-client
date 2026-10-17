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
        let response = response.into_message();
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
        Ok(client_response(
            &query,
            response,
            summary == DnssecSummary::Secure,
        ))
    }
}

fn client_response(query: &Message, mut response: Message, secure: bool) -> Message {
    let dnssec_ok = query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);
    // RFC 4035 §3.2.1：验证所需的记录不能泄漏给未请求 DNSSEC 的旧解析器。
    // 显式查询 DNSKEY 等类型仍须返回；投影必须在本机完成证明检查之后进行。
    if !dnssec_ok {
        for records in [
            &mut response.answers,
            &mut response.authorities,
            &mut response.additionals,
        ] {
            records.retain(|record| {
                !record.record_type().is_dnssec()
                    || query
                        .queries
                        .iter()
                        .any(|question| question.query_type() == record.record_type())
            });
        }
    }
    // RFC 6840 §5.6–5.8：DO 随原查询，AD 还要求客户端明确理解它。
    response.edns = query.edns.clone();
    response.metadata.authentic_data = secure && (dnssec_ok || query.metadata.authentic_data);
    response.metadata.id = query.metadata.id;
    response.metadata.checking_disabled = false;
    response
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
        dnssec::{
            Algorithm, PublicKeyBuf,
            rdata::{DNSKEY, DNSSECRData, NSEC},
        },
        op::{Edns, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType},
    };

    fn projection_records() -> Vec<Record> {
        let name = Name::from_ascii("signed.example.").unwrap();
        vec![
            Record::from_rdata(
                name.clone(),
                30,
                RData::from("192.0.2.10".parse::<std::net::IpAddr>().unwrap()),
            ),
            Record::from_rdata(
                name.clone(),
                30,
                RData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::new(
                    true,
                    true,
                    false,
                    PublicKeyBuf::new(vec![0; 32], Algorithm::ED25519),
                ))),
            ),
            Record::from_rdata(
                name.clone(),
                30,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    name,
                    [RecordType::A, RecordType::NSEC],
                ))),
            ),
        ]
    }

    #[test]
    fn response_ad_requires_local_validation_and_client_opt_in() {
        for secure in [false, true] {
            for request_ad in [false, true] {
                for request_do in [None, Some(false), Some(true)] {
                    let mut query = Message::query();
                    query.metadata.id = 1234;
                    query.metadata.authentic_data = request_ad;
                    query.metadata.checking_disabled = true;
                    if let Some(dnssec_ok) = request_do {
                        let mut edns = Edns::new();
                        edns.set_dnssec_ok(dnssec_ok).set_max_payload(1232);
                        query.edns = Some(edns);
                    }
                    let mut upstream = Message::response(5678, query.metadata.op_code);
                    upstream.metadata.authentic_data = true;
                    let mut upstream_edns = Edns::new();
                    upstream_edns.enable_dnssec();
                    upstream.edns = Some(upstream_edns);
                    let response = client_response(&query, upstream, secure);
                    assert_eq!(
                        response.metadata.authentic_data,
                        secure && (request_ad || request_do == Some(true))
                    );
                    assert_eq!(response.metadata.id, 1234);
                    assert!(!response.metadata.checking_disabled);
                    assert_eq!(response.edns, query.edns);
                }
            }
        }
    }

    #[test]
    fn legacy_response_strips_unrequested_dnssec_from_every_section() {
        for requested in [RecordType::A, RecordType::ANY, RecordType::DNSKEY] {
            let mut query = Message::query();
            query.queries.push(Query::query(
                Name::from_ascii("signed.example.").unwrap(),
                requested,
            ));
            let mut upstream = crate::dns::reply(&query, ResponseCode::NoError);
            upstream.answers = projection_records();
            upstream.authorities = projection_records();
            upstream.additionals = projection_records();
            let response = client_response(&query, upstream, true);
            for records in [
                &response.answers,
                &response.authorities,
                &response.additionals,
            ] {
                let types: Vec<_> = records.iter().map(Record::record_type).collect();
                assert_eq!(
                    types,
                    if requested == RecordType::DNSKEY {
                        vec![RecordType::A, RecordType::DNSKEY]
                    } else {
                        vec![RecordType::A]
                    }
                );
            }
            assert!(!response.metadata.authentic_data);
        }
    }

    #[test]
    fn dnssec_aware_response_keeps_records_and_original_edns() {
        let mut query = Message::query();
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true).set_max_payload(1232);
        query.edns = Some(edns);
        let mut upstream = crate::dns::reply(&query, ResponseCode::NoError);
        upstream.answers = projection_records();
        upstream.authorities = projection_records();
        upstream.additionals = projection_records();
        let response = client_response(&query, upstream.clone(), true);
        assert_eq!(response.answers, upstream.answers);
        assert_eq!(response.authorities, upstream.authorities);
        assert_eq!(response.additionals, upstream.additionals);
        assert!(response.metadata.authentic_data);
        assert_eq!(response.edns, query.edns);
    }

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
