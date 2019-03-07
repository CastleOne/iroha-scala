package net.cimadai.iroha

/**
  * Copyright Daisuke SHIMADA, Richard Gomes -  All Rights Reserved.
  * https://github.com/cimadai/iroha-scala
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *      http://www.apache.org/licenses/LICENSE-2.0
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

object Iroha {
  import iroha.protocol.commands.Command
  import iroha.protocol.commands.Command.Command._
  import iroha.protocol.endpoint.{CommandService_v1Grpc, QueryService_v1Grpc, ToriiResponse, TxStatus, TxStatusRequest}
  import iroha.protocol.primitive._
  import iroha.protocol.queries.Query
  import iroha.protocol.transaction.Transaction
  import iroha.protocol.{commands, queries}
  import net.cimadai.crypto.KeyPair
  import java.util.concurrent.atomic.AtomicLong

  type CmdStub = CommandService_v1Grpc.CommandService_v1Stub
  type QryStub = QueryService_v1Grpc.QueryService_v1Stub

  case class ToriiError(message: String, txStatus: TxStatus) extends Error(message)

  object ToriiError {
    def unapply(response: ToriiResponse): Option[ToriiError] = (response.errOrCmdName, response.txStatus) match {
      case (msg, TxStatus.STATELESS_VALIDATION_FAILED) => Some(ToriiError(s"Stateless Validation Failed: $msg", response.txStatus))
      case (msg, TxStatus.STATEFUL_VALIDATION_FAILED) => Some(ToriiError(s"Stateful Validation Failed: $msg", response.txStatus))
      case (msg, TxStatus.NOT_RECEIVED) => Some(ToriiError(s"Transaction Not Received: $msg", response.txStatus))
      case (msg, TxStatus.MST_EXPIRED) => Some(ToriiError(s"MST Expired: $msg", response.txStatus))
      case _ => None
    }
  }

  //--------------------------------------------------------------------------------------------------------------------

  trait Validation {
    import scala.util.{Failure, Success, Try}

    /** Parse domain name according to RFC1035 and RFC5891 */
    def parseDomainName(value: String): Try[String] =
      sizeDomainName(value)
        .flatMap(value => validateDomainName(value))

    private def sizeDomainName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthDomainName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"domain name must be (0,${lengthDomainName}] characters: ${value}"))

    private def validateDomainName(value: String): Try[String] =
      value match {
        case regexDomainName(_*) => Success(value)
        case _                   => Failure(new IllegalArgumentException(s"invalid domain name: ${value}"))
      }

    //credits: Regular Expressions Cookbook by Steven Levithan, Jan Goyvaerts
    //FIXME: https://github.com/frgomes/iroha-scala/issues/5
    /** Regular expression which matches a domain name */
    val regexDomainName = "^(xn--)?((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$".r

    /** Maximum length for a domain name */
    val lengthDomainName = 164

    //------------

    /** Parse any IPv4 address or IPv6 address or domain name */
    def parsePeerAddress(value: String): Try[String] =
      parseIPv4(value) orElse parseIPv6(value) orElse parseHostname(value)

    /** Parse IPv4 address */
    def parseIPv4(value: String): Try[String] = {
      def checkInvalid(address: String): Try[String] =
        if(address == "0.0.0.0") Failure(new java.net.UnknownHostException(address)) else Success(address)

      value.trim match {
        case regexIPv4(_*) => checkInvalid(value.trim)
        case _             => Failure(new IllegalArgumentException(s"invalid IPv4 address name: ${value}"))
      }
    }

    /** Parse IPv6 address */
    def parseIPv6(value: String): Try[String] =
      value.trim.toUpperCase match {
        case regexIPv6(_*) => Success(value)
        case _             => Failure(new IllegalArgumentException(s"invalid IPv4 address name: ${value}"))
      }

    /** Performs a DNS query, trying to resolve hostname. */
    def parseHostname(hostname: String): Try[String] = {
      def checkEmpty(hostname: String): Try[String] =
        if(hostname.length == 0) Failure(new java.net.UnknownHostException()) else Success(hostname)
      def resolve(hostname: String): Try[String] =
        Try { java.net.InetAddress.getByName(hostname).toString }
      def checkInvalid(address: String): Try[String] =
        if(address.startsWith("/"))  Failure(new java.net.UnknownHostException(address)) else Success(address)

      checkEmpty(hostname.trim)
        .flatMap(resolve)
        .flatMap(checkInvalid)
    }

    //credits: Regular Expressions Cookbook by Steven Levithan, Jan Goyvaerts
    /** Regular expression which matches a IPv4 address */
    val regexIPv4 = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$".r


    //credits: Regular Expressions Cookbook by Steven Levithan, Jan Goyvaerts
    /** Regular expression which matches a IPv6 address */
    val regexIPv6 = "^(?:(?:(?:[A-F0-9]{1,4}:){6}|(?=(?:[A-F0-9]{0,4}:){0,6}(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$)(([0-9A-F]{1,4}:){0,5}|:)((:[0-9A-F]{1,4}){1,5}:|:))(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:))$".r

    //------------

    /** Parse asset name */
    def parseAssetName(value: String): Try[String] =
      sizeAssetName(value)
        .flatMap(value => validateAssetName(value))

    private def sizeAssetName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthAssetName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"asset name must be (0,${lengthAssetName}] characters: ${value}"))

    private def validateAssetName(value: String): Try[String] =
      value match {
        case regexAssetName(_*) => Success(value)
        case _                  => Failure(new IllegalArgumentException(s"invalid asset name: ${value}"))
      }

    /** Regular expressions which matches an asset name */
    val regexAssetName = "^[A-Za-z0-9]+$".r

    /** Maximum length for an asset name */
    val lengthAssetName = 32

    //------------

    /** Parse account name */
    def parseAccountName(value: String): Try[String] =
      sizeAccountName(value)
        .flatMap(value => validateAccountName(value))

    private def sizeAccountName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthAccountName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"account name must be (0,${lengthAccountName}] characters: ${value}"))

    private def validateAccountName(value: String): Try[String] =
      value match {
        case regexAccountName(_*) => Success(value)
        case _                    => Failure(new IllegalArgumentException(s"invalid account name: ${value}"))
      }

    /** Regular expression which matches an account name */
    val regexAccountName = "^[a-z0-9_]+$".r

    /** Maximum length for an account name */
    val lengthAccountName = 32

    //----------

    /** Parse role name */
    def parseRoleName(value: String): Try[String] =
      sizeRoleName(value)
        .flatMap(value => validateRoleName(value))

    private def sizeRoleName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthRoleName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"role name must be (0,${lengthRoleName}] characters: ${value}"))

    private def validateRoleName(value: String): Try[String] =
      value match {
        case regexRoleName(_*) => Success(value)
        case _                 => Failure(new IllegalArgumentException(s"invalid role name: ${value}"))
      }

    /** Regular expressions which matches a role name */
    val regexRoleName = "^[A-Za-z0-9]+$".r

    /** Maximum length for a role name */
    val lengthRoleName = 45

    //----------

    def parseAmount(value: String): Try[String] = {
      def makeBigDecimal(value: String) = Try { BigDecimal.exact(value) }
      def checkNegative(value: String): Try[String] =
        if(value.startsWith("-")) Failure(new IllegalArgumentException(value)) else Success(value)

      checkNegative(value.trim)
        .flatMap(makeBigDecimal)
        .flatMap(number => parseAmount(number))
        .flatMap(number => Success(number.toString))
    }

    def parseAmount(value: BigDecimal): Try[BigDecimal] =
      if(value.doubleValue >= 0.0)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"amount must be greater or equal zero: ${value}"))

    //----------

    /** Parse description */
    def parseDescription(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthDescription)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"description must be (0,${lengthDescription}] characters: ${value}"))

    /** Maximum length for a transfer description */
    val lengthDescription = 64

  }

  //--------------------------------------------------------------------------------------------------------------------

  trait Display {
    def toString: String
  }

  trait Domain extends Display
  object Domain extends Validation {
    import scala.util.Try

    private case class impl(value: String) extends Domain {
      override def toString: String = value
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [Domain] from domain name */
    //FIXME: def task(domain: String): Task[Domain] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(domain)))

    /** Builds [Domain] from domain name */
    def apply(domain: String): Try[Domain] =
      parseDomainName(domain)
        .map(domain => impl(domain))
  }

  trait Account extends Display
  object Account extends Validation {
    import scala.util.Try

    private case class impl(value: String) extends Account {
      override def toString: String = value
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [Account] from account name and domain name */
    //FIXME: def task(account: String, domain: String): Task[Account] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(account, domain)))

    /** Builds [Account] from account name and domain name */
    def apply(account: String, domain: String): Try[Account] =
      for {
        _ <- parseAccountName(account)
        _ <- parseDomainName(domain)
      } yield {
        new impl(s"${account}@${domain}")
      }
  }

  trait Asset extends Display
  object Asset extends Validation {
    import scala.util.Try

    private case class impl(value: String) extends Asset {
      override def toString: String = value
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [Asset] from asset name and domain name */
    //FIXME: def task(asset: String, domain: String): Task[Asset] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(asset, domain)))

    /** Builds [Asset] from asset name and domain name */
    def apply(asset: String, domain: String): Try[Asset] =
      for {
        _ <- parseAssetName(asset)
        _ <- parseDomainName(domain)
      } yield {
        new impl(s"${asset}#${domain}")
      }
  }

  trait Role extends Display
  object Role extends Validation {
    import scala.util.Try

    private case class impl(value: String) extends Role  {
      override def toString: String = value
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [Role] from role name */
    //FIXME: def task(role: String): Task[Role] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(role)))

    /** Builds [Role] from role */
    def apply(role: String): Try[Role] =
      parseRoleName(role)
        .map(role => impl(role))
  }

  trait Amount extends Display
  object Amount extends Validation {
    import scala.util.Try

    private case class impl(value: BigDecimal) extends Amount {
      override def toString: String = value.doubleValue.toString
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [Amount] from [BigDecimal] */
    //FIXME: def task(amount: BigDecimal): Task[Amount] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(amount)))

    /** builds [Amount] from [BigDecimal] */
    def apply(amount: BigDecimal): Try[Amount] =
      parseAmount(amount)
        .map(amount => impl(amount))
  }

  trait Description extends Display
  object Description extends Validation {
    import scala.util.Try

    private case class impl(value: String) extends Description {
      override def toString: String = value.toString
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [Description] from [String] */
    //FIXME: def task(description: String): Task[Description] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(description)))

    /** builds [Description] from [String] */
    def apply(description: String): Try[Description] =
      parseDescription(description)
        .map(description => impl(description))
  }

  trait PeerAddress extends Display {
    def toPeer: Peer
  }
  object PeerAddress extends Validation {
    import net.cimadai.crypto.PublicKey
    import scala.util.Try

    private case class impl(address: String, publicKey: PublicKey) extends PeerAddress {
      override def toString: String = address.toString
      override def toPeer: Peer = iroha.protocol.primitive.Peer(address, publicKey.hexa)
    }

    //FIXME: import monix.eval.Task
    //FIXME: /** Asynchronously builds [PeerAddress] from [Domain] and a [EdDSAPublicKey] */
    //FIXME: def task(address: String, publicKey: SHA3EdDSAPublicKey): Task[PeerAddress] =
    //FIXME:   Task.defer(
    //FIXME:     Task.fromTry(
    //FIXME:       apply(address, publicKey)))

    /** builds [PeerAddress] from [Domain] and a [EdDSAPublicKey] */
    def apply(address: String, publicKey: PublicKey): Try[PeerAddress] =
      parsePeerAddress(address)
        .map(address => impl(address, publicKey))
  }

  //--------------------------------------------------------------------------------------------------------------------

  private val queryCounter = new AtomicLong(1) //FIXME: code review

  object CommandBuilder {
    import IrohaImplicits._
    import net.cimadai.crypto.Implicits._
    import net.cimadai.crypto.PublicKey
    import scala.util.Try

    def appendRole(account: Account, role: Role): Try[Command] = Try {
      Command(AppendRole(commands.AppendRole(account, role))) }

    def createRole(name: String, permissions: Seq[RolePermission]): Try[Command] = Try {
      Command(CreateRole(commands.CreateRole(name, permissions))) }

    def grantPermission(account: Account, permissions: GrantablePermission): Try[Command] = Try {
      Command(GrantPermission(commands.GrantPermission(account, permissions))) }

    def revokePermission(account: Account, permissions: GrantablePermission): Try[Command] = Try {
      Command(RevokePermission(commands.RevokePermission(account, permissions))) }

    def addPeer(peer: PeerAddress): Try[Command] = Try {
      Command(AddPeer(commands.AddPeer(Some(peer)))) }

    def addSignatory(account: Account, publicKey: PublicKey): Try[Command] = Try {
      Command(AddSignatory(commands.AddSignatory(account, publicKey.hexa))) }

    def createAccount(name: Account, domain: Domain, publicKey: PublicKey): Try[Command] = Try {
      Command(CreateAccount(commands.CreateAccount(name, domain, publicKey.hexa))) }

    def createAsset(name: String, domain: Domain, precision: Int): Try[Command] = Try {
      Command(CreateAsset(commands.CreateAsset(name, domain, precision))) }

    def createDomain(name: String, defaultRole: Role): Try[Command] = Try {
      Command(CreateDomain(commands.CreateDomain(name, defaultRole))) }

    def removeSignatory(account: Account, publicKey: PublicKey): Try[Command] = Try {
      Command(RemoveSignatory(commands.RemoveSignatory(account, publicKey.hexa))) }

    def setAccountQuorum(account: Account, quorum: Int): Try[Command] = Try {
      Command(SetAccountQuorum(commands.SetAccountQuorum(account, quorum))) }

    def addAssetQuantity(asset: Asset, amount: Amount): Try[Command] = Try {
      Command(AddAssetQuantity(commands.AddAssetQuantity(asset, amount))) }

    def subtractAssetQuantity(asset: Asset, amount: Amount): Try[Command] = Try {
      Command(SubtractAssetQuantity(commands.SubtractAssetQuantity(asset, amount))) }

    def transferAsset(srcAccount: Account, dstAccount: Account,
                      asset: Asset, description: Description, amount: Amount): Try[Command] = Try {
      Command(
        TransferAsset(
          commands.TransferAsset(
            srcAccount,
            dstAccount,
            asset,
            description,
            amount)))
    }

    //XXX private def txHash(transaction: Transaction): Array[Byte] = {
    //XXX   digest.digest(transaction.payload.get.toByteArray)
    //XXX }

    def txStatusRequest(transaction: Transaction): Try[TxStatusRequest] = Try {
      TxStatusRequest(transaction.payload.get.toByteArray.hexa) }
      //XXX TxStatusRequest(Utils.bytesToHex(Iroha.CommandService.txHash(transaction))) } //FIXME: Code review
  }

  object TransactionBuilder {
    import IrohaImplicits._
    import net.cimadai.crypto.Implicits._
    import scala.util.Try

    def transaction(creator: Account, creatorKeyPair: KeyPair, commands: Command*): Try[Transaction] = {
      val createdTime = System.currentTimeMillis()
      val maybeReducedPayload = commands.headOption
        .map(_ => Transaction.Payload.ReducedPayload(commands, creator, createdTime, 1))

      val payload = Transaction.Payload(reducedPayload = maybeReducedPayload)
      val privateKey = creatorKeyPair.privateKey
      val publicKey = creatorKeyPair.publicKey
      privateKey.sign(payload.toByteArray).map { signed =>
        val signature = Signature(publicKey.hexa, signed.hexa)
        Transaction(Some(payload), Seq(signature))
      }
    }
  }


  object CommandService {
    import com.google.protobuf.empty.Empty
    import monix.eval.Task
    import monix.execution.Scheduler
    import net.cimadai.crypto.Crypto
    import scala.util.control.NonFatal
    import net.cimadai.crypto.Implicits._
    import scala.concurrent.Future

    def send(tx: Transaction)(implicit stub: CmdStub, crypto: Crypto): Task[ToriiResponse] =
      request(tx)
        .redeemWith(
          t => Task.raiseError[ToriiResponse](t),
          _ => status(tx))

    def request(tx: Transaction)(implicit stub: CmdStub): Task[Empty] =
      Task.deferFutureAction { implicit scheduler: Scheduler =>
        try {
          stub.torii(tx)
        } catch {
          case NonFatal(t) => Future.failed[Empty](t)
        }
      }

    def status(tx: Transaction)(implicit stub: CmdStub, crypto: Crypto): Task[ToriiResponse] =
      Task.deferFutureAction { implicit scheduler: Scheduler =>
        val bytes: Array[Byte] = tx.getPayload.toByteArray
        val hash: String =  crypto.digest.digest(bytes).hexa
        val request = new TxStatusRequest(hash)
        try {
          stub.status(request)
        } catch {
          case NonFatal(t) => Future.failed[ToriiResponse](t)
        }
      }
  }


/*
  class CommandService_v1Stub(channel: _root_.io.grpc.Channel, options: _root_.io.grpc.CallOptions = _root_.io.grpc.CallOptions.DEFAULT) extends _root_.io.grpc.stub.AbstractStub[CommandService_v1Stub](channel, options) with CommandService_v1 {

    override def torii(request: iroha.protocol.transaction.Transaction): scala.concurrent.Future[com.google.protobuf.empty.Empty] = {
      _root_.scalapb.grpc.ClientCalls.asyncUnaryCall(channel, METHOD_TORII, options, request)
    }

    override def listTorii(request: iroha.protocol.endpoint.TxList): scala.concurrent.Future[com.google.protobuf.empty.Empty] = {
      _root_.scalapb.grpc.ClientCalls.asyncUnaryCall(channel, METHOD_LIST_TORII, options, request)
    }

    override def status(request: iroha.protocol.endpoint.TxStatusRequest): scala.concurrent.Future[iroha.protocol.endpoint.ToriiResponse] = {
      _root_.scalapb.grpc.ClientCalls.asyncUnaryCall(channel, METHOD_STATUS, options, request)
    }

    override def statusStream(request: iroha.protocol.endpoint.TxStatusRequest, responseObserver: _root_.io.grpc.stub.StreamObserver[iroha.protocol.endpoint.ToriiResponse]): Unit = {
      _root_.scalapb.grpc.ClientCalls.asyncServerStreamingCall(channel, METHOD_STATUS_STREAM, options, request, responseObserver)
    }

    override def build(channel: _root_.io.grpc.Channel, options: _root_.io.grpc.CallOptions): CommandService_v1Stub = new CommandService_v1Stub(channel, options)
  }
*/








  object QueryService {
    import net.cimadai.crypto.Implicits._
    import scala.util.Try

    private def createQuery(creator: Account, creatorKeyPair: KeyPair, query: Query.Payload.Query): Try[Query] = {
      val createdTime = System.currentTimeMillis()
      val payload =
        Query.Payload(
          meta = Some(
            queries.QueryPayloadMeta(
              createdTime = createdTime, creatorAccountId = creator.toString, queryCounter = queryCounter.getAndIncrement)),
          query = query)
      val privateKey = creatorKeyPair.privateKey
      val publicKey  = creatorKeyPair.publicKey
      privateKey.sign(payload.toByteArray).map { signed =>
        val signature = Some(Signature(publicKey.hexa, signed.hexa))
        Query(Some(payload), signature)
      }
    }

    def getAccount(creator: Account, creatorKeyPair: KeyPair, account: Account): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccount(queries.GetAccount(account.toString)))

    def getSignatories(creator: Account, creatorKeyPair: KeyPair, account: Account): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetSignatories(queries.GetSignatories(account.toString)))

    def getAccountTransactions(creator: Account, creatorKeyPair: KeyPair, account: Account): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccountTransactions(queries.GetAccountTransactions(account.toString)))

    def getAccountAssetTransactions(creator: Account, creatorKeyPair: KeyPair, account: Account, asset: Asset): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccountAssetTransactions(queries.GetAccountAssetTransactions(account.toString, asset.toString)))

    def getTransactions(creator: Account, creatorKeyPair: KeyPair, txHashes: Seq[Array[Byte]]): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetTransactions(queries.GetTransactions(txHashes.map(bytes => bytes.hexa))))

    def getAccountAssets(creator: Account, creatorKeyPair: KeyPair, account: Account): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccountAssets(queries.GetAccountAssets(account.toString)))

    def getAccountDetail(creator: Account, creatorKeyPair: KeyPair, account: Account): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccount(queries.GetAccount(account.toString)))

    def getRoles(creator: Account, creatorKeyPair: KeyPair): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetRoles(queries.GetRoles()))

    def getRolePermissions(creator: Account, creatorKeyPair: KeyPair, role: Role): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetRolePermissions(queries.GetRolePermissions(role.toString)))

    def getAssetInfo(creator: Account, creatorKeyPair: KeyPair, asset: Asset): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAssetInfo(queries.GetAssetInfo(asset.toString)))

    def getPendingTransactions(creator: Account, creatorKeyPair: KeyPair): Try[Query] =
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetPendingTransactions(queries.GetPendingTransactions()))
  }

  sealed trait MatchedResponse

  object MatchedResponse {
    import iroha.protocol.{qry_responses => Responses}
    case class AccountAssetsResponse(response: Responses.AccountAssetResponse) extends MatchedResponse
    case class AccountDetailResponse(response: Responses.AccountDetailResponse) extends MatchedResponse
    case class AccountResponse(response: Responses.AccountResponse) extends MatchedResponse
    case class ErrorResponse(response: Responses.ErrorResponse) extends MatchedResponse
    case class SignatoriesResponse(response: Responses.SignatoriesResponse) extends MatchedResponse
    case class TransactionsResponse(response: Responses.TransactionsResponse) extends MatchedResponse
    case class AssetResponse(response: Responses.AssetResponse) extends MatchedResponse
    case class RolesResponse(response: Responses.RolesResponse) extends MatchedResponse
    case class RolePermissionsResponse(response: Responses.RolePermissionsResponse) extends MatchedResponse
  }

  object QueryResponse {
    import MatchedResponse._
    import iroha.protocol.qry_responses.QueryResponse

    def unapply(arg: QueryResponse): Option[MatchedResponse] = arg.response match {
      case r if r.isAccountAssetsResponse => arg.response.accountAssetsResponse.map(AccountAssetsResponse.apply)
      case r if r.isAccountDetailResponse => arg.response.accountDetailResponse.map(AccountDetailResponse.apply)
      case r if r.isAccountResponse => arg.response.accountResponse.map(AccountResponse.apply)
      case r if r.isErrorResponse => arg.response.errorResponse.map(ErrorResponse.apply)
      case r if r.isSignatoriesResponse => arg.response.signatoriesResponse.map(SignatoriesResponse.apply)
      case r if r.isTransactionsResponse => arg.response.transactionsResponse.map(TransactionsResponse.apply)
      case r if r.isAssetResponse => arg.response.assetResponse.map(AssetResponse.apply)
      case r if r.isRolesResponse => arg.response.rolesResponse.map(RolesResponse.apply)
      case r if r.isRolePermissionsResponse => arg.response.rolePermissionsResponse.map(RolePermissionsResponse.apply)
      case _ => None
    }
  }
}
