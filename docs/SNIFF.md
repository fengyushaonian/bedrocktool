# Packet sniffer

`sniff` answers three questions about the server to client wire format that
cannot be settled from the schema alone, because the community schemas disagree
with each other and with the vanilla encoder:

1. Does an empty item stack still carry `count`, `metadata`, `stack id flag`,
   `block runtime id` and `extra`, or does it stop after the network id?
2. Does every entity metadata entry carry the extra `legacy_type` selector byte
   after `type`, and is it always equal to `type`?
3. Is the `move_player` teleport body prefixed with a bool, or switched on
   `mode` without a prefix?

It does not trust any of the candidate schemas. It parses the same bytes under
every plausible hypothesis and reports which one consumes the packet exactly.

## Usage

Live, through the proxy:

```bash
bedrocktool sniff -address play.example.com:19132 -out sniff.jsonl -max 2000
```

Then connect a client to the printed listen address (default
`0.0.0.0:19132`). The proxy connects to the real server with its own protocol
version, so the bytes observed are exactly what a client at that version
receives.

Offline, from a capture taken earlier with `bedrocktool capture`:

```bash
bedrocktool sniff -pcap captures/server.pcap2 -out sniff.jsonl
```

Offline mode needs no account and no server. It reads the `BTCP` container
directly and never decodes packets through gophertunnel, so a capture taken
with a different protocol version can still be analysed.

Common flags:

| flag | meaning |
| --- | --- |
| `-address` | server to proxy, required unless `-pcap` is used |
| `-listen` | local address the client connects to |
| `-out` | json lines output, one record per probed packet |
| `-max` | stop after N probed packets, `0` for no limit |
| `-verbose` | print every hypothesis, not only the winner |
| `-pcap` | analyse a pcap2 file instead of running a proxy |

## Reading the output

One line per packet:

```
[s2c] add_player  len=144 -> item=item-instance air=air-full legacy_type=true ... | item=0(8B) meta=4 legacy=4/4
```

* `item=0(8B)` means the held item had network id 0 (air) and occupied 8 bytes.
  If the server short circuited air this would read `2B` and the rest of the
  packet would not parse.
* `legacy=4/4` means all four metadata entries had a selector byte equal to
  their type. The parser rejects a hypothesis where they disagree, because
  vanilla treats that as a protocol error.
* `teleport(bool=true)` means the option prefix was present and set.

The run ends with an aggregate verdict:

```
verdict: item stack uses item-instance; empty stacks still carry all trailing fields (8 bytes);
         metadata entries carry a legacy_type byte; move_player always prefixes teleport with a bool
item-layout            item-instance    4/4 (100.0%)
air-layout             air-full         4/4 (100.0%)
metadata-legacy-type   present          5/5 (100.0%)
teleport-option        present          1/1 (100.0%)
passenger-of-block     absent           3/3 (100.0%)
metadata-sanity        selector byte equals type in 20/20 entries
```

Only packets that parse exactly under a single hypothesis vote. Ambiguous or
unexplained packets are counted but never change the verdict, so one truncated
frame cannot flip a conclusion. If a dimension shows a split (for example
`air-full 12/14`), the capture contains frames from two different server
versions or a packet the parser is still misreading: look at those frames with
`-verbose`.

## What is probed

| packet id | packet | dimensions |
| --- | --- | --- |
| 12 | add_player | item layout, air, metadata selector, passenger record |
| 13 | add_actor | metadata selector, passenger record |
| 15 | add_item_actor | item layout, air, metadata selector |
| 19 | move_player | teleport option |
| 31 | mob_equipment | item layout, air |
| 32 | mob_armour_equipment | item layout, air |
| 39 | set_actor_data | metadata selector |

`mob_equipment` is the cheapest test for the air question: the packet ends three
bytes after the item, so a wrong air length cannot hide.

## How the parse works

* `utils/packetsniff/reader.go` is a bounds checked reader with the exact
  primitives the protocol uses, including a network NBT skipper. The skipper is
  verified against `nbt.MarshalEncoding(..., nbt.NetworkLittleEndian)` in
  `sniff_test.go`, because network NBT mixes fixed and variable sized fields
  (shorts are fixed, ints and longs are zigzag varints, list counts are zigzag).
* `parse.go` mirrors the `Marshal` methods in `gophertunnel/minecraft/protocol`
  field by field. If a field is read at the wrong offset the packet will not end
  exactly, or a float will be infinite, or a bool will not be 0/1.
* `probe.go` runs the cartesian product of the dimensions that apply to a
  packet. Hypotheses that differ only in a dimension the payload cannot show
  (air handling of a non empty stack) are collapsed instead of reported as
  ambiguous.
* `pcap.go` reads the `BTCP` container: 16 byte header, resource pack zip, then
  records of `magic | size | direction | timestamp | s2 payload | magic`.

## Limits

* Only the server to client direction is probed. The three questions are about
  what the server writes; client packets are not needed.
* The parsers describe the protocol the bundled gophertunnel speaks. Analysing a
  capture from an older version can still work because the hypothesis search
  covers the older item layout and the presence or absence of the newer fields,
  but a field added in a version the parsers do not know will show up as
  `NO MATCH`.
* Resource pack chunk packets are never probed, they carry no entity data.
