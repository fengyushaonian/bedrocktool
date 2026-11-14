package packetsniff

import "fmt"

// ItemLayout selects between the two item stack encodings in the wild.
type ItemLayout int

const (
	// ItemLayoutV1 is the pre 1.26.40 Item: a zigzag32 network id and a
	// short circuit for air that ends the field after a single byte.
	ItemLayoutV1 ItemLayout = iota
	// ItemLayoutInstance is the ItemInstance used by 1.26.40 and later: a
	// fixed int16 network id, followed by the full field set even for air.
	ItemLayoutInstance
)

func (l ItemLayout) String() string {
	if l == ItemLayoutV1 {
		return "item-v1"
	}
	return "item-instance"
}

// AirMode selects whether an empty stack still carries the trailing fields.
type AirMode int

const (
	// AirShort ends an air stack right after its network id.
	AirShort AirMode = iota
	// AirFull writes count, metadata, stack id flag, block runtime id and a
	// zero length extra blob for air as well.
	AirFull
)

func (a AirMode) String() string {
	if a == AirShort {
		return "air-short"
	}
	return "air-full"
}

// Hypothesis is one candidate interpretation of a payload. Dimensions that do
// not apply to a packet are ignored by its parser, so the same struct is reused
// for every packet type.
type Hypothesis struct {
	Item ItemLayout

	// Air only matters when Item is ItemLayoutInstance: ItemLayoutV1 always
	// short circuits on air because that is how it is defined.
	Air AirMode

	// LegacyType adds one byte after the metadata type, mirroring the
	// cereal selector that vanilla writes.
	LegacyType bool

	// TeleportOption makes move_player carry a bool before the teleport body
	// regardless of mode, instead of switching on mode.
	TeleportOption bool

	// PassengerOfBlock adds an optional block passenger record after the
	// entity links.
	PassengerOfBlock bool
}

func (h Hypothesis) String() string {
	return fmt.Sprintf("item=%s air=%s legacy_type=%t teleport_option=%t passenger=%t",
		h.Item, h.Air, h.LegacyType, h.TeleportOption, h.PassengerOfBlock)
}

// Facts collects the values that are worth printing once a hypothesis parsed a
// packet successfully. They are filled in best effort: a failed hypothesis may
// still carry partial values, which is useful when diagnosing a mismatch.
type Facts struct {
	// HasItem reports whether this packet carries an item stack at all.
	HasItem bool
	// ItemNetworkID is the network id of the first item field found.
	ItemNetworkID int32
	// ItemBytes is how many bytes that item field occupied.
	ItemBytes int
	// ItemIsAir reports whether the item was an empty stack.
	ItemIsAir bool

	// MetaEntries is the number of metadata entries read.
	MetaEntries int
	// MetaLegacyMatch counts entries whose selector byte equalled the type.
	// A low count against a successful parse means the legacy byte theory
	// holds only by accident, so the report flags it.
	MetaLegacyMatch int
	// MetaCompound counts compound values, which need the NBT skipper.
	MetaCompound int

	// MoveMode is the raw mode byte of move_player.
	MoveMode uint8
	// TeleportPresent reports the value of the teleport option bool, when the
	// winning hypothesis had one.
	TeleportPresent bool
	// TeleportRead reports whether teleport fields were consumed.
	TeleportRead bool
}

// Parse reads one packet payload end to end under h. It returns the number of
// bytes consumed and an error if the payload runs out of bytes, contains an
// implausible value, or leaves trailing bytes unread: all three mean h does not
// describe this payload.
func Parse(packetID uint32, payload []byte, h Hypothesis) (Facts, int, error) {
	r := NewReader(payload)
	f := Facts{}

	switch packetID {
	case idAddPlayer:
		parseAddPlayer(r, h, &f)
	case idAddActor:
		parseAddActor(r, h, &f)
	case idAddItemActor:
		parseAddItemActor(r, h, &f)
	case idMovePlayer:
		parseMovePlayer(r, h, &f)
	case idMobEquipment:
		parseMobEquipment(r, h, &f)
	case idMobArmourEquipment:
		parseMobArmourEquipment(r, h, &f)
	case idSetActorData:
		parseSetActorData(r, h, &f)
	default:
		return f, r.Pos, fmt.Errorf("packet %d not probeable", packetID)
	}

	if r.Err != nil {
		return f, r.Pos, r.Err
	}
	if r.Remaining() != 0 {
		return f, r.Pos, fmt.Errorf("%d trailing bytes at offset %d", r.Remaining(), r.Pos)
	}
	return f, r.Pos, nil
}

func parseAddPlayer(r *Reader, h Hypothesis, f *Facts) {
	r.Skip(16) // uuid
	_ = r.String()
	r.VarU64()     // runtime id
	_ = r.String() // platform chat id
	r.Vec3f()      // position
	r.Vec3f()      // velocity
	r.F32()        // pitch
	r.F32()        // yaw
	r.F32()        // head yaw

	f.ItemNetworkID, f.ItemBytes = readItem(r, h)
	f.ItemIsAir = f.ItemNetworkID == 0
	f.HasItem = true

	r.ZigZag32() // game type
	readMetadata(r, h, f)
	readEntityProperties(r)
	readAbilityData(r)
	readEntityLinks(r)
	readOptionalPassenger(r, h)
	_ = r.String() // device id
	r.I32()        // build platform
}

func parseAddActor(r *Reader, h Hypothesis, f *Facts) {
	r.ZigZag64()   // unique id
	r.VarU64()     // runtime id
	_ = r.String() // entity type
	r.Vec3f()      // position
	r.Vec3f()      // velocity
	r.F32()        // pitch
	r.F32()        // yaw
	r.F32()        // head yaw
	r.F32()        // body yaw
	readAttributes(r)
	readMetadata(r, h, f)
	readEntityProperties(r)
	readEntityLinks(r)
	readOptionalPassenger(r, h)
}

func parseAddItemActor(r *Reader, h Hypothesis, f *Facts) {
	r.ZigZag64() // unique id
	r.VarU64()   // runtime id

	f.ItemNetworkID, f.ItemBytes = readItem(r, h)
	f.ItemIsAir = f.ItemNetworkID == 0
	f.HasItem = true

	r.Vec3f() // position
	r.Vec3f() // velocity
	readMetadata(r, h, f)
	r.Bool() // from fishing
}

func parseMovePlayer(r *Reader, h Hypothesis, f *Facts) {
	r.VarU64() // runtime id
	r.Vec3f()  // position
	r.F32()    // pitch
	r.F32()    // yaw
	r.F32()    // head yaw

	f.MoveMode = r.U8()
	r.Bool()   // on ground
	r.VarU64() // ridden runtime id

	switch {
	case h.TeleportOption:
		f.TeleportPresent = r.BoolStrict()
		if f.TeleportPresent {
			readTeleportBody(r, f)
		}
	case f.MoveMode == 2:
		readTeleportBody(r, f)
	}

	r.VarU64() // tick
}

// readTeleportBody consumes the teleport cause and source entity type. Both are
// small enumerated values, so an out of range number means the offset drifted.
func readTeleportBody(r *Reader, f *Facts) {
	cause := r.I32()
	entityType := r.I32()
	if r.Err != nil {
		return
	}
	if cause < 0 || cause > 4 {
		r.fail("teleport cause out of range: %d", cause)
		return
	}
	if entityType < 0 || entityType > 200 {
		r.fail("teleport source entity type out of range: %d", entityType)
		return
	}
	f.TeleportRead = true
}

func parseMobEquipment(r *Reader, h Hypothesis, f *Facts) {
	r.VarU64() // runtime id
	f.ItemNetworkID, f.ItemBytes = readItem(r, h)
	f.ItemIsAir = f.ItemNetworkID == 0
	f.HasItem = true
	r.U8() // inventory slot
	r.U8() // hotbar slot
	r.U8() // window id
}

func parseMobArmourEquipment(r *Reader, h Hypothesis, f *Facts) {
	r.VarU64() // runtime id
	for i := 0; i < 5; i++ {
		id, n := readItem(r, h)
		if i == 0 {
			f.ItemNetworkID, f.ItemBytes = id, n
			f.ItemIsAir = id == 0
			f.HasItem = true
		}
	}
}

func parseSetActorData(r *Reader, h Hypothesis, f *Facts) {
	r.VarU64() // runtime id
	readMetadata(r, h, f)
	readEntityProperties(r)
	r.VarU64() // tick
}

// readItem consumes one item stack and returns its network id and size in
// bytes. A network id of 0 is air.
func readItem(r *Reader, h Hypothesis) (id int32, size int) {
	start := r.Pos

	if h.Item == ItemLayoutV1 {
		id = r.ZigZag32()
		if r.Err != nil {
			return 0, 0
		}
		if id == 0 && h.Air == AirShort {
			return id, r.Pos - start
		}
		r.U16()    // count
		r.VarU32() // metadata value
		if r.Bool() {
			r.ZigZag32() // stack network id
		}
		r.ZigZag32() // block runtime id
		readItemExtra(r)
		return id, r.Pos - start
	}

	id = int32(r.I16())
	if r.Err != nil {
		return 0, 0
	}
	if id == 0 && h.Air == AirShort {
		return id, r.Pos - start
	}
	r.U16()    // count
	r.VarU32() // metadata value
	if r.Bool() {
		r.ZigZag32() // stack network id
	}
	r.VarU32() // block runtime id
	readItemExtra(r)
	return id, r.Pos - start
}

// readItemExtra consumes the length prefixed user data blob.
func readItemExtra(r *Reader) {
	n := r.VarU32()
	if r.Err != nil {
		return
	}
	if n > 1<<20 {
		r.fail("item extra too long: %d", n)
		return
	}
	r.Skip(int(n))
}

func readMetadata(r *Reader, h Hypothesis, f *Facts) {
	defer func() {
		// Vanilla validates the selector against the type and aborts if they
		// differ, so a mismatch means this hypothesis is the wrong one.
		if h.LegacyType && r.Err == nil && f.MetaEntries > 0 && f.MetaLegacyMatch != f.MetaEntries {
			r.fail("metadata selector mismatch: %d/%d", f.MetaLegacyMatch, f.MetaEntries)
		}
	}()

	count := r.VarU32()
	if r.Err != nil {
		return
	}
	if count > 512 {
		r.fail("metadata count implausible: %d", count)
		return
	}
	f.MetaEntries = int(count)

	for i := uint32(0); i < count; i++ {
		r.VarU32() // key
		dataType := r.VarU32()
		if r.Err != nil {
			return
		}
		if dataType > 8 {
			r.fail("metadata type %d out of range at entry %d", dataType, i)
			return
		}
		if h.LegacyType {
			legacy := r.U8()
			if r.Err != nil {
				return
			}
			if legacy == uint8(dataType) {
				f.MetaLegacyMatch++
			}
		}
		switch dataType {
		case 0:
			r.I8()
		case 1:
			r.I16()
		case 2:
			r.ZigZag32()
		case 3:
			r.F32()
		case 4:
			_ = r.String()
		case 5:
			r.SkipNBT()
			f.MetaCompound++
		case 6:
			r.Vec3i()
		case 7:
			r.ZigZag64()
		case 8:
			r.Vec3f()
		}
	}
}

func readEntityProperties(r *Reader) {
	n := r.VarU32()
	if r.Err != nil {
		return
	}
	if n > 4096 {
		r.fail("entity property count implausible: %d", n)
		return
	}
	for i := uint32(0); i < n; i++ {
		r.VarU32()
		r.ZigZag32()
	}

	n = r.VarU32()
	if r.Err != nil {
		return
	}
	if n > 4096 {
		r.fail("entity property count implausible: %d", n)
		return
	}
	for i := uint32(0); i < n; i++ {
		r.VarU32()
		r.F32()
	}
}

func readAttributes(r *Reader) {
	n := r.VarU32()
	if r.Err != nil {
		return
	}
	if n > 4096 {
		r.fail("attribute count implausible: %d", n)
		return
	}
	for i := uint32(0); i < n; i++ {
		_ = r.String()
		r.F32()
		r.F32()
		r.F32()
	}
}

func readAbilityData(r *Reader) {
	r.I64() // entity unique id
	r.U8()  // player permissions
	r.U8()  // command permissions

	n := r.VarU32()
	if r.Err != nil {
		return
	}
	if n > 16 {
		r.fail("ability layer count implausible: %d", n)
		return
	}
	for i := uint32(0); i < n; i++ {
		r.U16()
		r.U32()
		r.U32()
		r.F32()
		r.F32()
		r.F32()
	}
}

func readEntityLinks(r *Reader) {
	n := r.VarU32()
	if r.Err != nil {
		return
	}
	if n > 64 {
		r.fail("entity link count implausible: %d", n)
		return
	}
	for i := uint32(0); i < n; i++ {
		r.ZigZag64()
		r.ZigZag64()
		r.U8()
		r.Bool()
		r.Bool()
		r.F32()
	}
}

func readOptionalPassenger(r *Reader, h Hypothesis) {
	if !h.PassengerOfBlock {
		return
	}
	if !r.Bool() {
		return
	}
	r.Vec3i() // block position
	r.Vec3f() // offset
	r.F32()   // rotation
	r.F32()   // rotation limit
	r.U8()    // emote type
}
