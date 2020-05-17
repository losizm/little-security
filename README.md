# little-security

The Scala library that adds a little security to applications.

[![Maven Central](https://img.shields.io/maven-central/v/com.github.losizm/little-security_2.13.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.github.losizm%22%20AND%20a:%22little-security.12%22)

## Getting Started
To use **little-security**, start by adding it to your project.

```scala
libraryDependencies += "com.github.losizm" %% "little-security" % "0.1.0"
```

## How It Works

**little-security** is powered by a pair of traits: `Permission` and
`SecurityContext`.

A `Permission` is defined by a given name, and one or more permissions can be
applied to a restricted operation.

A `SecurityContext` establishes a pattern in which a restricted operation is
performed only if its required permissions are granted. Otherwise, a
`SecurityViolation` is raised.

## Security in Action

The following script provides an example of how read/write access to an
in-memory cache can be regulated.

```scala
import little.security.{ Permission, SecurityContext, UserSecurity }

import scala.collection.concurrent.TrieMap

object SecureCache {
  // Define permissions for reading and writing cache entries
  private val getPermission = Permission("cache:get")
  private val setPermission = Permission("cache:set")

  private val cache = TrieMap[String, Array[Byte]](
    "gang starr"      -> "step in the arena".getBytes("utf-8"),
    "digable planets" -> "blowout comb".getBytes("utf-8")
  )

  def get(key: String)(implicit security: SecurityContext): Array[Byte] =
    // Tests for read permission before getting cache entry
    security(getPermission) { () =>
      copy(cache(key))
    }

  def set(key: String, data: Array[Byte])(implicit security: SecurityContext): Unit =
    // Tests for write permission before setting cache entry
    security(setPermission) { () =>
      cache += key -> copy(data)
    }

  private def copy(data: Array[Byte]): Array[Byte] =
    Array.copyOf(data, data.size)
}

// Create security context for user with read permission to cache
implicit val user = UserSecurity("guest", "staff", Permission("cache:get"))

// Get cache entry
val data = SecureCache.get("gang starr")

// Throw SecurityViolation because user lacks write permission
SecureCache.set("sucker mc", data)
```

## Testing Permissions

At times, it may be enough to simply check a permission to see whether it is
granted, and not necessarily throw a `SecurityViolation` if it isn't. That's
precisely what `SecurityContext.test(Permission)` is for. It returns `true` or
`false` based on the permission being granted or not. It's an ideal predicate to
a security filter, as demonstrated in the following script.

```scala
object SecureMessages {
  // Define class to encapsulate text message and assigned permission
  private case class Message(text: String, permission: Permission)

  private val messages = Seq(
    Message("This is public message #1."   , Permission("public")),
    Message("This is public message #2."   , Permission("public")),
    Message("This is private message #1."  , Permission("private")),
    Message("This is public message #3."   , Permission("public")),
    Message("This is protected message #1.", Permission("protected"))
  )

  def list(implicit security: SecurityContext): Seq[String] =
    // Filter messages by testing permission
    messages.filter(msg => security.test(msg.permission))
      .map(_.text)
}

// Create user with "public" and "protected" permissions.
implicit val user = UserSecurity("guest", "staff",
  Permission("public"),
  Permission("protected")
)

// Print all accessible messages
SecureMessages.list.foreach(println)
```

## User and Group Permissions

A permission is defined by its name, and you're free to implement any convention
for the names used in your application. However, there are two notable
exceptions, which are related to how the names of user and group permissions are
created.

A user permission is created with `UserPermission`. There's no implementing
class; it's just a factory. It constructs a permission with a specially
formatted name using user and group identiers.

```scala
val userPermission = UserPermission("guest", "staff")
```

And `GroupPermission` constructs a permission with a specially formatted name
using a group identifier only.

```scala
val groupPermission = GroupPermission("staff")
```

When an instance of `UserSecurity` is created, user and group permissions are
appended to the permissions expressly supplied in the constructor.

```scala
val user = UserSecurity("guest", "staff", Permission("filesystem:read"))

assert(user.test(Permission("filesystem:read")))
assert(user.test(UserPermission("guest", "staff")))
assert(user.test(GroupPermission("staff")))
```

## The Omnipotent RootSecurity

In the examples so far, we've used `UserSecurity`, which is a security context
with a finite set of granted permissions.

The only other type is `RootSecurity`, which grants all permissions. That is,
there's no permission it doesn't have. It's the _superuser_ security context.

`RootSecurity` is an object implementation, so there's only one instance of it.
It should be used for the purpose of effectively bypassing security checks.

```scala
// Print all messages
SecureMessages.list(RootSecurity).foreach(println)

(0 to 999999).foreach { _ =>
  // Create permission with randomly generated name
  val perm = Permission(scala.util.Random.nextString(8))

  // Assert permission is granted
  assert(RootSecurity.test(perm))
}
```

## API Documentation

See [scaladoc](https://losizm.github.io/little-security/latest/api/little/security/index.html)
for additional details.

## License
**little-security** is licensed under the Apache License, Version 2. See [LICENSE](LICENSE)
for more information.
