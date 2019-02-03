name := "iroha-scala"

version := "1.0.4"

organization := "castleone"

licenses += ("Apache-2.0", url("https://www.apache.org/licenses/LICENSE-2.0.html"))

val PROJECT_SCALA_VERSION = "2.12.6"

scalaVersion := PROJECT_SCALA_VERSION

useGpg in GlobalScope := true

lazy val libraries = Seq(
  "org.scala-lang.modules" %% "scala-xml" % "1.1.0",
  "org.scala-lang.modules" %% "scala-parser-combinators" % "1.1.1",
  "io.grpc" % "grpc-netty-shaded" % "1.13.1",
  "com.trueaccord.scalapb" %% "scalapb-runtime-grpc" % com.trueaccord.scalapb.compiler.Version.scalapbVersion,
  "com.trueaccord.scalapb" %% "scalapb-runtime" % com.trueaccord.scalapb.compiler.Version.scalapbVersion % "protobuf",
  "org.bouncycastle" % "bcpg-jdk15on" % "1.58",
  "net.i2p.crypto" % "eddsa" % "0.2.0",
  "org.scalatest" %% "scalatest" % "3.0.5" % "test"
)

lazy val settings = Seq(
  organization := "org.hyperledger",
  scalaVersion := PROJECT_SCALA_VERSION,
  javacOptions ++= Seq("-source", "1.8", "-target", "1.8", "-encoding", "UTF-8"),
  javaOptions ++= Seq("-Xmx1G"),
  scalacOptions ++= Seq(
    "-target:jvm-1.8",
    "-encoding", "UTF-8",
    "-unchecked",
    "-deprecation",
    "-Xfuture",
    "-Yno-adapted-args",
    "-Ywarn-dead-code",
    "-Ywarn-numeric-widen",
    "-Ywarn-value-discard",
    "-Ywarn-unused"
  ),
  libraryDependencies ++= libraries,

  fork in Test := true,

  publishMavenStyle := false,

  publishArtifact in Test := false,

  pomIncludeRepository := { _ => false }
)

lazy val irohaScala = (project in file("."))
  .settings(settings: _*)
  .settings(
    name := "iroha-scala",
    organization := "com.castleone",
    bintrayRepository := "iroha-scala",
    bintrayOrganization in bintray := None
)
  .enablePlugins(ProtocPlugin)
  .settings(
    PB.targets in Compile := Seq(
      scalapb.gen() -> (sourceManaged in Compile).value
    ),
    PB.protoSources in Compile := Seq(file("protos"))
  )
