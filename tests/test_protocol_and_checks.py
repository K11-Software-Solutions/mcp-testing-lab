"""The protocol model, each server's behaviour, and each check."""
import pytest

from mcplab import checks as C
from mcplab import servers as S
from mcplab.protocol import INVALID_PARAMS, METHOD_NOT_FOUND, PROTOCOL_VERSION, request, validate


def test_initialize_and_list():
    s = S.notes()
    init = request(s, "initialize")["result"]
    assert init["protocolVersion"] == PROTOCOL_VERSION and init["serverInfo"]["name"] == "notes"
    tools = request(s, "tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["add_note", "search_notes"]
    assert all({"name", "description", "inputSchema"} <= set(t) for t in tools)


def test_calls_errors_and_codes():
    s = S.notes()
    assert request(s, "tools/call", {"name": "add_note", "arguments": {"text": "hi"}})["result"]["isError"] is False
    assert request(s, "tools/call", {"name": "add_note", "arguments": {}})["error"]["code"] == INVALID_PARAMS
    assert request(s, "tools/call", {"name": "nope", "arguments": {}})["error"]["code"] == INVALID_PARAMS
    assert request(s, "bogus")["error"]["code"] == METHOD_NOT_FOUND
    assert s.handle('{"jsonrpc": "2.0", "method": "notifications/initialized"}') is None    # no reply to notifications


def test_schema_validation():
    schema = S.EMAIL_SCHEMA
    assert validate(schema, {"to": "a", "subject": "b", "body": "c"}) == []
    assert "missing 'body'" in validate(schema, {"to": "a", "subject": "b"})
    assert "unexpected 'x'" in validate(schema, {"to": "a", "subject": "b", "body": "c", "x": 1})
    assert "'to' must be string" in validate(schema, {"to": 1, "subject": "b", "body": "c"})


def test_good_servers_pass_every_check():
    for make in S.GOOD.values():
        s = make()
        tools = request(s, "tools/list")["result"]["tools"]
        assert C.conformance(make()) == [] and C.list_stability(make()) == [] and C.error_hygiene(make()) == []
        assert C.scan_descriptions(tools) == []


def test_sloppy_server_accepts_invalid_arguments():
    assert any("accepted invalid arguments" in f for f in C.conformance(S.sloppy()))


def test_rug_pull_changes_tools_without_notification():
    assert C.list_stability(S.rugpull()) == ["tools/list: tool definitions changed without a list_changed notification"]


def test_a_declared_change_is_not_a_stability_failure():
    s = S.notes()
    request(s, "tools/list")
    s.change_tools(s.tools[:1])                       # sends notifications/tools/list_changed
    assert C.list_stability(s) == []


def test_leaky_errors_are_flagged():
    assert C.error_hygiene(S.leaky()) and "internals" in C.error_hygiene(S.leaky())[0]


@pytest.mark.parametrize("variant, caught", [("plain", True), ("hidden characters", True), ("paraphrased", False)])
def test_description_scanner_and_its_blind_spot(variant, caught):
    tools = request(S.poisoned(S.POISON_VARIANTS[variant]), "tools/list")["result"]["tools"]
    assert bool(C.scan_descriptions(tools)) is caught


def test_cross_server_references_only_for_distinctive_names():
    tools = request(S.shadowing(), "tools/list")["result"]["tools"]
    found = C.scan_descriptions(tools, {"send_email", "add"})
    assert any("send_email" in f for f in found) and not any("(add" in f for f in found)


def test_manifest_detects_any_change_and_names_a_same_version_change():
    pinned = C.manifest(S.notes())
    assert C.compare_manifest("notes", C.manifest(S.notes()), pinned) == []
    changed = C.compare_manifest("notes", C.manifest(S.drifting()), pinned)
    assert changed and "without a version bump" in changed[0]
    assert "not on the approved list" in C.compare_manifest("x", pinned, None)[0]


def test_collisions():
    assert C.collisions([S.notes(), S.mailer(), S.collider()]) == ["collision: tool 'send_email' offered by mailer, helpful-tools"]
    assert C.collisions([S.notes(), S.mailer()]) == []
