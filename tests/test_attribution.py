from attribution import record_email_attribution
from event_queue import event_queue
from swarm_graph import PheromoneGraph


def test_email_attribution_creates_nodes_and_reciprocal_clique():
    event_queue.reset()
    graph = PheromoneGraph()

    affected = record_email_attribution(
        "email-1",
        {
            "domains": ["fraud.example"],
            "ips": ["198.51.100.20"],
            "upi_ids": ["fraud@upi"],
        },
        graph,
    )

    assert affected == [
        "email_domain:fraud.example",
        "email_ip:198.51.100.20",
        "upi_id:fraud@upi",
    ]
    assert graph.graph.number_of_nodes() == 3
    assert graph.graph.number_of_edges() == 6
    assert graph.graph.edges[affected[0], affected[1]]["signal_types"] == ["email_campaign"]
    assert graph.graph.nodes[affected[0]]["metadata"]["observation_count"] == 1
    assert event_queue.stats()["current_depth"] == 3
    event_queue.reset()


def test_repeated_attribution_reinforces_edges_and_observations():
    event_queue.reset()
    graph = PheromoneGraph()
    indicators = {"domains": ["fraud.example"], "ips": ["198.51.100.20"]}

    record_email_attribution("email-1", indicators, graph)
    record_email_attribution("email-2", indicators, graph)

    domain_id = "email_domain:fraud.example"
    ip_id = "email_ip:198.51.100.20"
    edge = graph.graph.edges[domain_id, ip_id]
    assert edge["weight"] == 2.0
    assert edge["reinforcement_count"] == 2
    assert graph.graph.nodes[domain_id]["metadata"]["observation_count"] == 2
    assert graph.graph.nodes[domain_id]["metadata"]["last_email_id"] == "email-2"
    event_queue.reset()


def test_attribution_with_all_indicator_types_and_backend():
    from graph_backend import InMemoryBackend, RedisGraphBackend
    event_queue.reset()

    for backend in (InMemoryBackend(), RedisGraphBackend()):
        affected = record_email_attribution(
            "email-99",
            {
                "domains": ["phish.net"],
                "ips": ["1.2.3.4"],
                "asns": ["AS12345"],
                "upi_ids": ["scammer@okaxis"],
                "reply_tos": ["bounce@phish.net"],
            },
            backend,
        )
        assert len(affected) == 5
        assert backend.node_count() == 5
        assert backend.edge_count() == 20  # 5 * 4 = 20 directed edges in Kn clique
        assert backend.get_node(affected[0])["metadata"]["last_email_id"] == "email-99"
        event_queue.reset()

