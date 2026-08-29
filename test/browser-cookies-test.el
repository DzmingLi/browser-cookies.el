;;; browser-cookies-test.el --- Tests for browser-cookies  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later

(require 'ert)
(require 'browser-cookies)

(defmacro browser-cookies-test--with-profile (&rest body)
  "Create a temporary Firefox profile and evaluate BODY."
  (declare (indent 0) (debug t))
  `(let* ((profile-directory (make-temp-file "browser-cookies-test-" t))
          (database-path (expand-file-name "cookies.sqlite" profile-directory))
          (database (sqlite-open database-path)))
     (unwind-protect
         (progn
           (sqlite-execute
            database
            (concat
             "CREATE TABLE moz_cookies ("
             "name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, "
             "isSecure INTEGER, creationTime INTEGER, originAttributes TEXT)"))
           ,@body)
       (when database (sqlite-close database))
       (delete-directory profile-directory t))))

(defun browser-cookies-test--insert
    (database name value domain path expiry secure creation &optional container)
  "Insert one Firefox cookie into DATABASE."
  (sqlite-execute
   database
   (concat
    "INSERT INTO moz_cookies "
    "(name, value, host, path, expiry, isSecure, creationTime, "
    "originAttributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
   (list name value domain path expiry secure creation (or container ""))))

(ert-deftest browser-cookies-filters-and-orders-firefox-cookies ()
  (browser-cookies-test--with-profile
    (let ((future (+ (floor (float-time)) 3600))
          (past (- (floor (float-time)) 3600)))
      (browser-cookies-test--insert
       database "root" "one" ".example.com" "/" future 0 1)
      (browser-cookies-test--insert
       database "account" "two" ".example.com" "/account" future 1 2)
      (browser-cookies-test--insert
       database "host-only" "three" "www.example.com" "/" future 0 3)
      (browser-cookies-test--insert
       database "expired" "no" ".example.com" "/" past 0 4)
      (browser-cookies-test--insert
       database "wrong-path" "no" ".example.com" "/other" future 0 5)
      (browser-cookies-test--insert
       database "container" "no" ".example.com" "/" future 0 6
       "^userContextId=2")
      (should
       (equal
        (browser-cookies-get
         "https://www.example.com/account/settings"
         :profile-directory profile-directory)
        '(("account" . "two")
          ("root" . "one")
          ("host-only" . "three")))))))

(ert-deftest browser-cookies-does-not-send-secure-cookie-over-http ()
  (browser-cookies-test--with-profile
    (browser-cookies-test--insert
     database "secure" "secret" ".example.com" "/" 0 1 1)
    (should-not
     (browser-cookies-get
      "http://example.com/" :profile-directory profile-directory))))

(ert-deftest browser-cookies-selects-explicit-firefox-container ()
  (browser-cookies-test--with-profile
    (browser-cookies-test--insert
     database "session" "ordinary" ".example.com" "/" 0 0 1)
    (browser-cookies-test--insert
     database "session" "container" ".example.com" "/" 0 0 2
     "^userContextId=2")
    (should
     (equal
      (browser-cookies-get
       "https://example.com/"
       :profile-directory profile-directory
       :origin-attributes "^userContextId=2")
      '(("session" . "container"))))))

(ert-deftest browser-cookies-formats-header ()
  (browser-cookies-test--with-profile
    (browser-cookies-test--insert
     database "first" "1" ".example.com" "/" 0 0 1)
    (browser-cookies-test--insert
     database "second" "2" ".example.com" "/" 0 0 2)
    (should
     (equal
      (browser-cookies-header
       "https://example.com/" :profile-directory profile-directory)
      "first=1; second=2"))))

(ert-deftest browser-cookies-reads-plaintext-chromium-cookie ()
  (let* ((profile-directory (make-temp-file "browser-cookies-chromium-" t))
         (network-directory (expand-file-name "Network" profile-directory))
         (database-path (expand-file-name "Cookies" network-directory))
         database)
    (unwind-protect
        (progn
          (make-directory network-directory)
          (setq database (sqlite-open database-path))
          (sqlite-execute database "CREATE TABLE meta (key TEXT, value TEXT)")
          (sqlite-execute database
                          "INSERT INTO meta (key, value) VALUES ('version', '24')")
          (sqlite-execute
           database
           (concat
            "CREATE TABLE cookies ("
            "host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, "
            "path TEXT, expires_utc INTEGER, is_secure INTEGER, "
            "has_expires INTEGER, creation_utc INTEGER, "
            "top_frame_site_key TEXT)"))
          (sqlite-execute
           database
           (concat
            "INSERT INTO cookies "
            "(host_key, name, value, encrypted_value, path, expires_utc, "
            "is_secure, has_expires, creation_utc, top_frame_site_key) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
           (list ".example.com" "session" "plain" "" "/" 0 1 0 1 ""))
          (should
           (equal
            (browser-cookies-get
             "https://example.com/"
             :browser 'chromium
             :profile-directory profile-directory)
            '(("session" . "plain")))))
      (when database (sqlite-close database))
      (delete-directory profile-directory t))))

(provide 'browser-cookies-test)
;;; browser-cookies-test.el ends here
