(ns buddy.test_buddy_auth
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.crypto.core :refer :all]
            [buddy.auth :refer [throw-notauthorized]]
            [buddy.auth.backends.httpbasic :refer [http-basic]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-request
  [username, password]
  (if (and username password)
    {:headers {"authorization" (format "Basic %s" (str->base64 (format "%s:%s" username password)))}}
    {:headers {}}))

(defn auth-fn
  [request parsed-data]
  (let [username (:username parsed-data)]
    (cond
      (= username "foo") :foo
      :else :anonymous)))

(deftest authentication-middleware-test
  (testing "Auth middleware with http-basic backend 01"
    (let [backend (http-basic :realm "Foo")
          handler (fn [req] req)
          handler (wrap-authentication handler backend)
          req     (make-request "user" "pass")
          resp    (handler req)]
        (is (nil? (:identity resp)))))

  (testing "Auth middleware with http-basic backend 02"
    (let [backend (http-basic :realm "Foo" :authfn auth-fn)
          handler (fn [req] req)
          handler (wrap-authentication handler backend)]
      (let [req   (make-request "user" "pass")
            resp  (handler req)]
        (is (= (:identity resp) :anonymous)))
      (let [req   (make-request "foo" "pass")
            resp  (handler req)]
        (is (= (:identity resp) :foo))))))

(deftest authorization-middleware-test
  (testing "Auth middleware with http-basic backend 01"
    (let [backend (http-basic :realm "Foo" :authfn auth-fn)
          handler (fn [req] (if (= (:identity req) :anonymous)
                              (throw-notauthorized {:msg "FooMsg"})
                              req))
          handler (wrap-authentication handler backend)
          handler (wrap-authorization handler backend)
          req     (make-request "user" "pass")
          resp    (handler req)]
      (println resp))))