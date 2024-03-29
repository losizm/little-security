organization := "com.github.losizm"
name         := "little-security"
version      := "1.1.0"
description  := "The Scala library that adds a little security to applications"
homepage     := Some(url("https://github.com/losizm/little-security"))
licenses     := List("Apache License, Version 2" -> url("http://www.apache.org/licenses/LICENSE-2.0.txt"))

scalaVersion := "3.0.2"

scalacOptions := Seq("-deprecation", "-feature", "-new-syntax", "-Yno-experimental")

Compile / doc / scalacOptions := Seq("-project", name.value, "-project-version", version.value)

libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.9" % "test"

developers := List(
  Developer(
    id    = "losizm",
    name  = "Carlos Conyers",
    email = "carlos.conyers@hotmail.com",
    url   = url("https://github.com/losizm")
  )
)

scmInfo := Some(
  ScmInfo(
    url("https://github.com/losizm/little-security"),
    "scm:git@github.com:losizm/little-security.git"
  )
)

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org"
  isSnapshot.value match {
    case true  => Some("snaphsots" at s"$nexus/content/repositories/snapshots")
    case false => Some("releases"  at s"$nexus/service/local/staging/deploy/maven2")
  }
}

pomIncludeRepository := (_ => false)
