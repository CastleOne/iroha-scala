package net.cimadai.iroha

import iroha.protocol.primitive
import net.cimadai.iroha.Iroha.{IrohaAccountId, IrohaAssetId, IrohaPeer, IrohaRoleId, IrohaTransferDescription}

object IrohaImplicits {
  implicit def formatAccountId(irohaAccountId: IrohaAccountId): String = irohaAccountId.toString
  implicit def formatAssetId(irohaAssetId: IrohaAssetId): String = irohaAssetId.toString
  implicit def formatRoleId(irohaRoleId: IrohaRoleId): String = irohaRoleId.toString
  implicit def formatTransferDescription(transferDescription: IrohaTransferDescription): String = transferDescription.toString
  implicit def primitivePeer(peer: IrohaPeer): primitive.Peer = primitive.Peer(peer.address, peer.byteString)
  implicit def maybePrimitivePeer(peer: Option[IrohaPeer]): Option[primitive.Peer] = peer.map(implicitly(_))
}
