use super::*;
use serde_json::json;

#[test]
fn heartbeat_only_accepts_fresh_matching_single_use_pongs() {
    let mut heartbeat = Heartbeat::default();
    assert!(heartbeat.pong(&[0; 8]).is_none());
    let nonce = heartbeat.ping().unwrap();
    let mut wrong = nonce;
    wrong[0] ^= 1;
    assert!(heartbeat.pong(&wrong).is_none());
    assert!(heartbeat.ping().is_err());
    assert!(heartbeat.pong(&nonce).is_some());
    assert!(heartbeat.pong(&nonce).is_none());
    let nonce = heartbeat.ping().unwrap();
    heartbeat.0.as_mut().unwrap().1 -= Duration::from_secs(15);
    assert!(heartbeat.pong(&nonce).is_none());
    assert!(heartbeat.ping().is_err());
}

fn map() -> DerpMap {
    serde_json::from_value(json!({"Regions": {
        "1": {"Nodes": [{"HostName": "127.0.0.1", "DERPPort": 1}]},
        "2": {"Nodes": [{"HostName": "127.0.0.1", "DERPPort": 2}]},
        "900": {"Nodes": [{"HostName": "127.0.0.1", "DERPPort": 900}]}
    }}))
    .unwrap()
}

fn connect(hub: &mut Hub, region: u16, rtt: u64) -> watch::Sender<Option<Duration>> {
    let (health, received) = watch::channel(Some(Duration::from_millis(rtt)));
    hub.workers.get_mut(&region).unwrap().health = received;
    health
}

#[tokio::test]
async fn only_confirmed_live_relays_are_advertised_and_preferred() {
    let map = map();
    let mut hub = Hub::default();
    let (incoming, _received) = mpsc::channel(16);
    hub.update(&map, &[1, 2], [1; 32], incoming.clone())
        .unwrap();
    assert_eq!(hub.home_region(), 0);
    assert!(
        hub.workers
            .values()
            .all(|worker| !*worker.preferred.borrow())
    );

    let second = connect(&mut hub, 2, 90);
    let live = connect(&mut hub, 900, 20);
    hub.update(&map, &[1, 2], [1; 32], incoming.clone())
        .unwrap();
    assert_eq!(hub.home_region(), 900);
    assert!(*hub.workers[&900].preferred.borrow());
    assert!(!*hub.workers[&1].preferred.borrow());
    assert!(!*hub.workers[&2].preferred.borrow());

    second.send_replace(Some(Duration::from_millis(1)));
    hub.update(&map, &[1, 2], [1; 32], incoming.clone())
        .unwrap();
    assert_eq!(hub.home_region(), 900);

    live.send_replace(None);
    assert_eq!(hub.home_region(), 0);
    hub.update(&map, &[1, 2], [1; 32], incoming.clone())
        .unwrap();
    assert_eq!(hub.home_region(), 2);
    assert!(!hub.workers.contains_key(&900));
    second.send_replace(None);
    assert_eq!(hub.home_region(), 0);
    hub.update(&map, &[1, 2], [1; 32], incoming).unwrap();
    assert_eq!(hub.home_region(), 0);
}

#[tokio::test]
async fn changed_definition_invalidates_confirmation_and_region_removal_stops_worker() {
    let mut map = map();
    let mut hub = Hub::default();
    let (incoming, _received) = mpsc::channel(16);
    hub.update(&map, &[2], [1; 32], incoming.clone()).unwrap();
    let health = connect(&mut hub, 900, 5);
    hub.update(&map, &[2], [1; 32], incoming.clone()).unwrap();
    assert_eq!(hub.home_region(), 900);

    map.regions.get_mut(&900).unwrap().nodes[0].cert_name = "new.example.test".into();
    hub.update(&map, &[2], [1; 32], incoming.clone()).unwrap();
    assert_eq!(hub.home_region(), 0);
    assert!(health.is_closed());
    assert!(hub.workers[&900].health.borrow().is_none());
    map.regions.remove(&900);
    hub.update(&map, &[2], [1; 32], incoming).unwrap();
    assert!(!hub.workers.contains_key(&900));
}

#[tokio::test]
async fn no_home_regions_are_peer_only_and_stun_only_regions_are_not_connected() {
    let mut map = map();
    map.regions.get_mut(&1).unwrap().no_measure_no_home = true;
    map.regions.get_mut(&2).unwrap().nodes[0].stun_only = true;
    let mut hub = Hub::default();
    let (incoming, _received) = mpsc::channel(16);
    hub.update(&map, &[1, 2], [1; 32], incoming.clone())
        .unwrap();
    assert!(!hub.workers.contains_key(&2));
    let _health = connect(&mut hub, 1, 1);
    hub.update(&map, &[1], [1; 32], incoming.clone()).unwrap();
    assert_eq!(hub.home_region(), 0);
    assert!(!*hub.workers[&1].preferred.borrow());
    hub.update(&map, &[], [1; 32], incoming).unwrap();
    assert!(!hub.workers.contains_key(&1));
    assert!(hub.workers.contains_key(&900));
}

#[tokio::test]
async fn bounded_home_search_rotates_past_unreachable_initial_regions() {
    let mut map = map();
    for region in 3..=8 {
        map.regions.insert(region, map.regions[&1].clone());
    }
    let mut hub = Hub::default();
    let (incoming, _received) = mpsc::channel(16);
    hub.update(&map, &[], [1; 32], incoming.clone()).unwrap();
    let initial = hub.workers.keys().copied().collect::<Vec<_>>();
    assert_eq!(initial, vec![1, 2, 3, 4]);
    hub.update(&map, &[], [1; 32], incoming.clone()).unwrap();
    assert_eq!(hub.workers.keys().copied().collect::<Vec<_>>(), initial);
    for worker in hub.workers.values_mut() {
        worker.started -= Duration::from_secs(16);
    }
    hub.update(&map, &[], [1; 32], incoming.clone()).unwrap();
    assert_eq!(
        hub.workers.keys().copied().collect::<Vec<_>>(),
        vec![5, 6, 7, 8]
    );
    for worker in hub.workers.values_mut() {
        worker.started -= Duration::from_secs(16);
    }
    hub.update(&map, &[], [1; 32], incoming.clone()).unwrap();
    assert!(hub.workers.contains_key(&900));
    assert_eq!(hub.workers.len(), 4);
    let _health = connect(&mut hub, 900, 50);
    hub.update(&map, &[], [1; 32], incoming).unwrap();
    assert_eq!(hub.home_region(), 900);
    assert_eq!(hub.workers.len(), 1);
}
