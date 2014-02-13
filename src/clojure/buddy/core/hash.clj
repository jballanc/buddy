(ns buddy.core.hash
  "Basic crypto primitives that used for more high
  level abstractions."
  (:require [buddy.codecs :refer :all]
  (:import (java.security MessageDigest)))

(defn digest
  "Generic function for create cryptographic hash. Given an algorithm
name and many parts as byte array. Returns a computed hash as byte array.
This function hides java api to `java.security.MessageDigest`"
  [algorithm & parts]
  (let [md (MessageDigest/getInstance algorithm)]
    (doseq [part parts]
      (.update md part))
    (.digest md)))

;; Alias for low level interface for all supported
;; secure hash algorithms. All of them return alway
;; array of bytes.
(def make-sha256 (partial digest "SHA-256"))
(def make-sha384 (partial digest "SHA-384"))
(def make-sha512 (partial digest "SHA-512"))
(def make-sha1 (partial digest "SHA-1"))
(def make-md5 (partial digest "MD5"))

;; Alias of same secure hash algorithms previously
;; defined but return human readable hexadecimal 
;; encoded output.
(def sha256 (comp make-sha256 bytes->hex))
(def sha384 (comp make-sha384 bytes->hex))
(def sha512 (comp make-sha512 bytes->hex))
(def sha1 (comp make-sha1 bytes->hex))
(def md5 (comp make-md5 bytes->hex))
