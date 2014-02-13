(ns buddy.crypto.signing.jwt
  "Clojure implementation of JSON Web Token RFC
defined on http://self-issued.info/docs/draft-jones-json-web-token-01.html"
  (:require [buddy.crypto.core :refer [hmac-sha256]]
            [buddy.codecs :refer :all]
            [clojure.string :as str]
            [clojure.data.json :as json])
  (:import (org.apache.commons.codec.binary Base64)))


(defn- json-encode [data] (json/write-str data))
(defn- json-decode [data] (json/read-str data :key-fn keyword))

(defn- base64-encode
  "Urlsafe without padding base64 encode function."
  [data]
  (-> (str->bytes data)
      (base64->str)
      (str/replace #"=" "")))

(defn- base64-decode
  "Urlsafe without padding base64 decode function."
  [data]
  (let [md (mod (count data) 4)
        px (case md
             2 "=="
             3 "="
             "")]
    (-> (str s px)
        (base64->bytes)
        (bytes->str))))

(defn- make-header
  [type algo]
  (-> {:typ type :alg algo}
      (json-encode)
      (base64-encode)))

(defn- make-payload
  [data]
  (-> (json-encode data)
      (base64-encode)))

(defn- make-signature
  [key algorithm]
  (let [key    (cond
                (string? key) (str->bytes key)
                (bytes? key) key)
        signfn (case algorithm
                 :hs256 (fn [data] (hmac-sha256 data key)))]
    ;; TODO
    ))
