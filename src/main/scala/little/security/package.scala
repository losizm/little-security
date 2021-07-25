/*
 * Copyright 2021 Carlos Conyers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package little

/**
 * Defines security model based on permissions granted to effective context.
 *
 * == How It Works ==
 *
 *  '''little-security''' is powered by a pair of traits: [[Permission]] and
 * [[SecurityContext]].
 * 
 * A `Permission` is defined with a given name, and one or more permissions can
 * be applied to a restricted operation.
 * 
 * A `SecurityContext` establishes a pattern in which a restricted operation is
 * performed only if its required permissions are granted. Otherwise, a
 * [[SecurityViolation]] is raised.
 *
 * == Security in Action ==
 *
 * The following script demonstrates how read/write access to an in-memory cache
 * could be implemented.
 *
 * {{{
 * import little.security.{ Permission, SecurityContext, UserContext }
 *
 * import scala.collection.concurrent.TrieMap
 *
 * object SecureCache:
 *   // Define permissions for reading and writing cache entries
 *   private val getPermission = Permission("cache:get")
 *   private val putPermission = Permission("cache:put")
 *
 *   private val cache = TrieMap[String, String](
 *     "gang starr"      -> "step in the arena",
 *     "digable planets" -> "blowout comb"
 *   )
 *
 *   def get(key: String)(using security: SecurityContext): String =
 *     // Test for read permission before getting cache entry
 *     security(getPermission) { cache(key) }
 *
 *   def put(key: String, value: String)(using security: SecurityContext): Unit =
 *     // Test for write permission before putting cache entry
 *     security(putPermission) { cache += key -> value }
 *
 * // Create security context for user with read permission to cache
 * given SecurityContext = UserContext("losizm", "staff", Permission("cache:get"))
 *
 * // Get cache entry
 * val classic = SecureCache.get("gang starr")
 *
 * // Throw SecurityViolation because user lacks write permission
 * SecureCache.put("sucker mc", classic)
 * }}}
 */
package object security
