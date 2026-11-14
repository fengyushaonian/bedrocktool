package packetsniff

import "github.com/sandertv/gophertunnel/minecraft/protocol/packet"

// Packet ids are taken from gophertunnel instead of being written out here, so
// the sniffer can never drift from the protocol the proxy actually speaks.
const (
	idAddPlayer          = packet.IDAddPlayer
	idAddActor           = packet.IDAddActor
	idAddItemActor       = packet.IDAddItemActor
	idMovePlayer         = packet.IDMovePlayer
	idMobEquipment       = packet.IDMobEquipment
	idMobArmourEquipment = packet.IDMobArmourEquipment
	idSetActorData       = packet.IDSetActorData
)

// Names maps the probed packet ids to a stable label used in reports.
var Names = map[uint32]string{
	idAddPlayer:          "add_player",
	idAddActor:           "add_actor",
	idAddItemActor:       "add_item_actor",
	idMovePlayer:         "move_player",
	idMobEquipment:       "mob_equipment",
	idMobArmourEquipment: "mob_armour_equipment",
	idSetActorData:       "set_actor_data",
}

// Interesting reports whether id is one of the packets the sniffer inspects.
func Interesting(id uint32) bool {
	_, ok := Names[id]
	return ok
}
