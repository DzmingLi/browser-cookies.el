;;; browser-cookies.el --- Read cookies from browser profiles  -*- lexical-binding: t; -*-

;; Copyright (C) 2026 Dzming Li

;; Author: Dzming Li <i@dzming.li>
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1"))
;; Keywords: comm, convenience
;; URL: https://github.com/DzmingLi/browser-cookies.el

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;;; Commentary:

;; Read the cookies applicable to an HTTP(S) URL directly from an explicitly
;; selected browser profile.  The package applies domain, path, secure,
;; expiration, and Firefox container rules before returning an alist suitable
;; for an HTTP client.
;;
;; The profile is never guessed or scanned.  This keeps account selection an
;; explicit user decision and avoids accidentally mixing browser identities.
;; Firefox is supported initially; the public API leaves room for additional
;; browser backends without changing callers.

;;; Code:

(require 'cl-lib)
(require 'sqlite)
(require 'subr-x)
(require 'url-parse)
(require 'url-util)

(defgroup browser-cookies nil
  "Read cookies from explicitly selected browser profiles."
  :group 'comm
  :prefix "browser-cookies-")

(defcustom browser-cookies-browser 'firefox
  "Default browser backend used by `browser-cookies-get'."
  :type '(choice
          (const :tag "Firefox" firefox)
          (const :tag "Chromium" chromium)
          (const :tag "Google Chrome" chrome)
          (const :tag "Microsoft Edge" edge))
  :group 'browser-cookies)

(defcustom browser-cookies-profile-directory nil
  "Default browser profile directory.

This must be set explicitly.  For Firefox, it is the directory containing
cookies.sqlite."
  :type '(choice (const :tag "Not configured" nil)
                 (directory :must-match t))
  :group 'browser-cookies)

(defcustom browser-cookies-firefox-origin-attributes ""
  "Exact Firefox `originAttributes' value to select.

The empty string is Firefox's ordinary, non-container context.  A container
can be selected explicitly with a value such as `^userContextId=2'."
  :type 'string
  :group 'browser-cookies)

(cl-defstruct (browser-cookies--record
               (:constructor browser-cookies--make-record))
  "Cookie read from a browser database before URL filtering."
  name value domain path expires secure creation)

(declare-function
 dbus-call-method "dbus"
 (bus service path interface method &rest args))
(declare-function secrets-list-collections "secrets" ())
(declare-function secrets-search-item-paths "secrets" (collection &rest attributes))
(declare-function secrets-get-secret "secrets" (collection item))

(defconst browser-cookies--chromium-browser-specs
  '((chromium
     :secret-applications ("chromium")
     :kwallet-folder "Chromium Keys"
     :kwallet-key "Chromium Safe Storage")
    (chrome
     :secret-applications ("chrome")
     :kwallet-folder "Chrome Keys"
     :kwallet-key "Chrome Safe Storage")
    (edge
     :secret-applications ("chromium")
     :kwallet-folder "Chromium Keys"
     :kwallet-key "Chromium Safe Storage"))
  "Chromium browser identifiers used by desktop credential stores.")

(defconst browser-cookies--chromium-linux-v10-key
  (unibyte-string
   #xfd #x62 #x1f #xe5 #xa2 #xb4 #x02 #x53
   #x9d #xfa #x14 #x7c #xa9 #x27 #x27 #x78)
  "AES-128 key used by Chromium's Linux basic password store.")

(defconst browser-cookies--chromium-aes-cbc-iv
  (encode-coding-string (make-string 16 ?\s) 'us-ascii t)
  "Fixed IV used by Chromium v10/v11 AES-CBC cookies.")

(defconst browser-cookies--chromium-time-epoch-offset 11644473600000000
  "Number of Chromium microseconds between its epoch and the Unix epoch.")

(defun browser-cookies--url-parts (url)
  "Parse URL and return (HOST PATH SECURE).

URL must be an absolute HTTP or HTTPS URL with a host."
  (let* ((parsed (url-generic-parse-url url))
         (host (url-host parsed))
         (scheme (downcase (or (url-type parsed) "")))
         (filename (or (url-filename parsed) "/"))
         (path (car (split-string filename "[?#]" t))))
    (unless (and (stringp host)
                 (not (string-empty-p host))
                 (member scheme '("http" "https")))
      (error "browser-cookies: URL must be absolute HTTP(S): %s" url))
    (list (downcase host)
          (if (and path (string-prefix-p "/" path)) path "/")
          (string-equal scheme "https"))))

(defun browser-cookies--domain-matches-p (domain host)
  "Return non-nil when cookie DOMAIN applies to HOST."
  (let ((domain (downcase domain))
        (host (downcase host)))
    (if (string-prefix-p "." domain)
        (let ((bare (substring domain 1)))
          (or (string-equal host bare)
              (string-suffix-p (concat "." bare) host)))
      (string-equal domain host))))

(defun browser-cookies--domain-candidates (host)
  "Return browser database domain candidates for HOST."
  (let ((candidates (list host (concat "." host)))
        (start 0))
    (while (string-match "\\." host start)
      (push (substring host (match-beginning 0)) candidates)
      (setq start (match-end 0)))
    (delete-dups candidates)))

(defun browser-cookies--path-matches-p (cookie-path request-path)
  "Return non-nil when COOKIE-PATH applies to REQUEST-PATH."
  (let ((cookie-path (if (string-empty-p cookie-path) "/" cookie-path)))
    (or (string-equal cookie-path request-path)
        (and (string-prefix-p cookie-path request-path)
             (or (string-suffix-p "/" cookie-path)
                 (and (> (length request-path) (length cookie-path))
                      (eq (aref request-path (length cookie-path)) ?/)))))))

(defun browser-cookies--records-to-alist (records)
  "Convert RECORDS to an alist in RFC 6265 transmission order."
  (mapcar
   (lambda (record)
     (cons (browser-cookies--record-name record)
           (browser-cookies--record-value record)))
   (cl-stable-sort
    (copy-sequence records)
    (lambda (left right)
      (let ((left-length (length (browser-cookies--record-path left)))
            (right-length (length (browser-cookies--record-path right))))
        (if (= left-length right-length)
            (< (or (browser-cookies--record-creation left) 0)
               (or (browser-cookies--record-creation right) 0))
          (> left-length right-length)))))))

(defun browser-cookies--records-for-url (records url)
  "Filter RECORDS for URL and return a cookie alist."
  (pcase-let* ((`(,host ,path ,secure) (browser-cookies--url-parts url))
               (now (float-time))
               (applicable
                (cl-remove-if-not
                 (lambda (record)
                   (and
                    (browser-cookies--domain-matches-p
                     (browser-cookies--record-domain record) host)
                    (browser-cookies--path-matches-p
                     (browser-cookies--record-path record) path)
                    (or (not (browser-cookies--record-secure record)) secure)
                    (or (null (browser-cookies--record-expires record))
                        (> (browser-cookies--record-expires record) now))))
                 records)))
    (browser-cookies--records-to-alist applicable)))

(defun browser-cookies--store-file (browser profile-directory)
  "Return BROWSER's cookie store inside PROFILE-DIRECTORY."
  (unless (and (stringp profile-directory)
               (not (string-empty-p (string-trim profile-directory))))
    (error "browser-cookies: set an explicit profile directory"))
  (let* ((profile (expand-file-name profile-directory))
         (relative
          (pcase browser
            ('firefox "cookies.sqlite")
            ((or 'chromium 'chrome 'edge) "Network/Cookies")
            (_ (error "browser-cookies: unsupported browser: %S" browser))))
         (file (expand-file-name relative profile)))
    (unless (and (file-directory-p profile) (file-readable-p profile))
      (error "browser-cookies: profile directory is not readable: %s" profile))
    (unless (and (file-regular-p file) (file-readable-p file))
      (error "browser-cookies: cookie database is not readable: %s" file))
    file))

(defun browser-cookies--sqlite-readonly-uri (path)
  "Convert PATH to a safely escaped read-only SQLite URI."
  (concat "file:"
          (url-hexify-string
           (expand-file-name path)
           (cons ?/ url-unreserved-chars))
          "?mode=ro&cache=private"))

(defun browser-cookies--query-database (path query)
  "Run QUERY against the browser database at PATH.

QUERY receives a database handle and schema name.  First attach the browser
database read-only.  If SQLite cannot read the live database, retry against a
temporary database/WAL snapshot."
  (let ((run-query
         (lambda (database schema)
           (let (transaction)
             (unwind-protect
                 (progn
                   (sqlite-execute database "BEGIN")
                   (setq transaction t)
                   (prog1 (funcall query database schema)
                     (sqlite-execute database "COMMIT")
                     (setq transaction nil)))
               (when transaction
                 (ignore-errors (sqlite-execute database "ROLLBACK"))))))))
    (condition-case readonly-error
        (let (database)
          (unwind-protect
              (progn
                ;; `sqlite-open' lacks a read-only argument.  Attach the browser
                ;; database to an in-memory main database using a read-only URI.
                (setq database (sqlite-open))
                (sqlite-execute
                 database "ATTACH DATABASE ? AS cookies"
                 (list (browser-cookies--sqlite-readonly-uri path)))
                (funcall run-query database "cookies"))
            (when database
              (ignore-errors (sqlite-close database)))))
      (sqlite-error
       (condition-case snapshot-error
           (let (snapshot-directory database)
             (unwind-protect
                 (let ((snapshot-name (file-name-nondirectory path)))
                   (setq snapshot-directory
                         (make-temp-file "browser-cookies-snapshot-" t))
                   (dolist (suffix '("" "-wal" "-shm"))
                     (let ((source (concat path suffix)))
                       (when (file-readable-p source)
                         (copy-file
                          source
                          (expand-file-name
                           (concat snapshot-name suffix)
                           snapshot-directory)
                          t))))
                   (setq database
                         (sqlite-open
                          (expand-file-name snapshot-name snapshot-directory)))
                   (funcall run-query database "main"))
               (when database
                 (ignore-errors (sqlite-close database)))
               (when snapshot-directory
                 (ignore-errors (delete-directory snapshot-directory t)))))
         (error
          (error
           "browser-cookies: database read failed (read-only: %s; snapshot: %s)"
           (error-message-string readonly-error)
           (error-message-string snapshot-error))))))))

(defun browser-cookies--select-firefox (database schema url origin-attributes)
  "Select cookies for URL from Firefox DATABASE and SCHEMA.

Only cookies with the exact ORIGIN-ATTRIBUTES value are considered."
  (pcase-let* ((`(,host ,_path ,_secure) (browser-cookies--url-parts url))
               (domains (browser-cookies--domain-candidates host))
               (placeholders (mapconcat (lambda (_domain) "?") domains ","))
               (table (concat schema ".moz_cookies"))
               (rows
                (sqlite-select
                 database
                 (concat
                  "SELECT name, value, host, path, expiry, isSecure, "
                  "creationTime FROM " table " WHERE host IN ("
                  placeholders ") AND originAttributes = ?")
                 (append domains (list origin-attributes))))
               (records
                (mapcar
                 (lambda (row)
                   (let ((expiry (nth 4 row)))
                     (browser-cookies--make-record
                      :name (nth 0 row)
                      :value (nth 1 row)
                      :domain (nth 2 row)
                      :path (or (nth 3 row) "/")
                      :expires (and (numberp expiry)
                                    (not (zerop expiry))
                                    (if (> expiry 100000000000)
                                        (/ expiry 1000.0)
                                      expiry))
                      :secure (not (zerop (or (nth 5 row) 0)))
                      :creation (nth 6 row))))
                 rows)))
    (browser-cookies--records-for-url records url)))

(defun browser-cookies--read-firefox (path url origin-attributes)
  "Read cookies for URL from Firefox database PATH.

ORIGIN-ATTRIBUTES selects the exact Firefox container context."
  (browser-cookies--query-database
   path
   (lambda (database schema)
     (browser-cookies--select-firefox
      database schema url origin-attributes))))

(defun browser-cookies--chromium-browser-spec (browser)
  "Return desktop credential-store configuration for BROWSER."
  (or (cdr (assq browser browser-cookies--chromium-browser-specs))
      (error "browser-cookies: unsupported Chromium browser: %S" browser)))

(defun browser-cookies--hmac-sha1-bytes (key bytes)
  "Return the raw HMAC-SHA1 of BYTES using KEY."
  (require 'gnutls)
  (unless (and (fboundp 'gnutls-hash-mac)
               (assq 'SHA1 (gnutls-macs)))
    (error "browser-cookies: this Emacs/GnuTLS lacks HMAC-SHA1"))
  ;; GnuTLS clears string keys, so pass a copy rather than caller-owned data.
  (gnutls-hash-mac 'SHA1 (copy-sequence key) bytes))

(defun browser-cookies--xor-byte-strings (left right)
  "Return the bytewise XOR of equal-length strings LEFT and RIGHT."
  (unless (= (length left) (length right))
    (error "browser-cookies: internal PBKDF2 length mismatch"))
  (let ((output (copy-sequence left)))
    (dotimes (index (length output))
      (aset output index (logxor (aref output index) (aref right index))))
    output))

(defun browser-cookies--pbkdf2-hmac-sha1
    (password salt iterations length)
  "Derive LENGTH bytes from PASSWORD and SALT using PBKDF2-HMAC-SHA1."
  (unless (and (integerp iterations) (> iterations 0)
               (integerp length) (> length 0))
    (error "browser-cookies: invalid PBKDF2 parameters"))
  (let ((block 1)
        (output (unibyte-string)))
    (while (< (length output) length)
      (let* ((counter
              (unibyte-string
               (logand (ash block -24) #xff)
               (logand (ash block -16) #xff)
               (logand (ash block -8) #xff)
               (logand block #xff)))
             (unit (browser-cookies--hmac-sha1-bytes
                    password (concat salt counter)))
             (accumulator (copy-sequence unit)))
        (dotimes (_ (1- iterations))
          (setq unit (browser-cookies--hmac-sha1-bytes password unit)
                accumulator
                (browser-cookies--xor-byte-strings accumulator unit)))
        (setq output (concat output accumulator)
              block (1+ block))))
    (substring output 0 length)))

(defun browser-cookies--chromium-secret-service-password (spec)
  "Read the Chromium safe-storage password described by SPEC."
  (require 'secrets)
  (unless (and (boundp 'secrets-enabled) (symbol-value 'secrets-enabled))
    (error "browser-cookies: Secret Service is unavailable"))
  (let ((collections
         (delete-dups (cons "default" (secrets-list-collections))))
        secret)
    (condition-case read-error
        (dolist (application (plist-get spec :secret-applications))
          (dolist (collection collections)
            (unless secret
              (dolist
                  (item
                   (secrets-search-item-paths
                    collection
                    :xdg:schema "chrome_libsecret_os_crypt_password_v2"
                    :application application))
                (unless secret
                  (setq secret (secrets-get-secret collection item)))))))
      (error
       (error "browser-cookies: Secret Service lookup failed: %s"
              (error-message-string read-error))))
    (unless (and (stringp secret) (not (string-empty-p secret)))
      (error "browser-cookies: browser safe-storage key was not found"))
    (encode-coding-string secret 'utf-8 t)))

(defconst browser-cookies--chromium-kwallet-endpoints
  '(("org.kde.kwalletd6" "/modules/kwalletd6")
    ("org.kde.kwalletd5" "/modules/kwalletd5")
    ("org.kde.kwalletd" "/modules/kwalletd"))
  "Known KDE KWallet D-Bus services and object paths.")

(defun browser-cookies--chromium-kwallet-password-at (endpoint spec)
  "Read SPEC's safe-storage password from KWallet ENDPOINT."
  (require 'dbus)
  (let* ((service (car endpoint))
         (path (cadr endpoint))
         (interface "org.kde.KWallet")
         (application "browser-cookies.el")
         handle)
    (unwind-protect
        (progn
          (unless (dbus-call-method
                   :session service path interface "isEnabled")
            (error "KWallet is disabled"))
          (let ((wallet (dbus-call-method
                         :session service path interface "networkWallet")))
            (setq handle
                  (dbus-call-method
                   :session service path interface "open"
                   wallet :int64 0 application)))
          (unless (and (integerp handle) (>= handle 0))
            (error "KWallet could not be opened"))
          (unless (dbus-call-method
                   :session service path interface "hasFolder"
                   :int32 handle (plist-get spec :kwallet-folder) application)
            (error "KWallet has no browser key folder"))
          (unless (dbus-call-method
                   :session service path interface "hasEntry"
                   :int32 handle
                   (plist-get spec :kwallet-folder)
                   (plist-get spec :kwallet-key)
                   application)
            (error "KWallet has no browser safe-storage key"))
          (let ((password
                 (dbus-call-method
                  :session service path interface "readPassword"
                  :int32 handle
                  (plist-get spec :kwallet-folder)
                  (plist-get spec :kwallet-key)
                  application)))
            (unless (and (stringp password) (not (string-empty-p password)))
              (error "KWallet browser key is empty"))
            (encode-coding-string password 'utf-8 t)))
      (when (and (integerp handle) (>= handle 0))
        (ignore-errors
          (dbus-call-method
           :session service path interface "close"
           :int32 handle nil application))))))

(defun browser-cookies--chromium-kwallet-password (spec)
  "Read SPEC's safe-storage password from an available KDE KWallet."
  (let (password last-error)
    (dolist (endpoint browser-cookies--chromium-kwallet-endpoints)
      (unless password
        (condition-case read-error
            (setq password
                  (browser-cookies--chromium-kwallet-password-at endpoint spec))
          (error (setq last-error read-error)))))
    (or password
        (error "browser-cookies: KWallet lookup failed: %s"
               (if last-error
                   (error-message-string last-error)
                 "no available service")))))

(defun browser-cookies--chromium-linux-password (spec)
  "Read SPEC's safe-storage password from the Linux desktop."
  (condition-case secret-service-error
      (browser-cookies--chromium-secret-service-password spec)
    (error
     (condition-case kwallet-error
         (browser-cookies--chromium-kwallet-password spec)
       (error
        (error
         "browser-cookies: key lookup failed (Secret Service: %s; KWallet: %s)"
         (error-message-string secret-service-error)
         (error-message-string kwallet-error)))))))

(defun browser-cookies--chromium-v10-key ()
  "Return the GNU/Linux Chromium v10 key."
  (unless (eq system-type 'gnu/linux)
    (error "browser-cookies: Chromium cookie decryption is unsupported here"))
  (copy-sequence browser-cookies--chromium-linux-v10-key))

(defun browser-cookies--chromium-v11-key (spec)
  "Return the Chromium v11 key described by SPEC on this system."
  (unless (eq system-type 'gnu/linux)
    (error "browser-cookies: Chromium v11 cookies are unsupported here"))
  (let ((password (browser-cookies--chromium-linux-password spec)))
    (unwind-protect
        (browser-cookies--pbkdf2-hmac-sha1
         password (encode-coding-string "saltysalt" 'us-ascii t) 1 16)
      (clear-string password))))

(defun browser-cookies--pkcs7-unpad (bytes block-size)
  "Validate and remove PKCS#7 padding from BYTES of BLOCK-SIZE."
  (let* ((length (length bytes))
         (padding (and (> length 0) (aref bytes (1- length)))))
    (unless (and (integerp padding)
                 (> padding 0)
                 (<= padding block-size)
                 (<= padding length)
                 (cl-loop for index from (- length padding) below length
                          always (= (aref bytes index) padding)))
      (error "browser-cookies: invalid Chromium AES padding"))
    (substring bytes 0 (- length padding))))

(defun browser-cookies--chromium-aes-cbc-decrypt (key ciphertext)
  "Decrypt Chromium AES-CBC CIPHERTEXT using KEY."
  (require 'gnutls)
  (unless (and (fboundp 'gnutls-symmetric-decrypt)
               (assq 'AES-128-CBC (gnutls-ciphers)))
    (error "browser-cookies: this Emacs/GnuTLS lacks AES-128-CBC"))
  (let ((result
         (gnutls-symmetric-decrypt
          'AES-128-CBC
          (copy-sequence key)
          browser-cookies--chromium-aes-cbc-iv
          ciphertext)))
    (unless (and (consp result) (stringp (car result)))
      (error "browser-cookies: Chromium AES decryption failed"))
    (browser-cookies--pkcs7-unpad (car result) 16)))

(defun browser-cookies--chromium-decrypt-cookie
    (encrypted-value host-key database-version keys)
  "Decrypt ENCRYPTED-VALUE and validate its HOST-KEY domain binding."
  (unless (and (stringp encrypted-value) (>= (length encrypted-value) 3))
    (error "browser-cookies: invalid Chromium cookie ciphertext"))
  (let* ((prefix (substring encrypted-value 0 3))
         (key-entry (assoc-string prefix keys)))
    (unless key-entry
      (error "browser-cookies: unsupported Chromium encryption: %s" prefix))
    (condition-case decrypt-error
        (let ((plaintext
               (browser-cookies--chromium-aes-cbc-decrypt
                (cdr key-entry) (substring encrypted-value 3))))
          (when (>= database-version 24)
            (let ((domain-hash
                   (secure-hash
                    'sha256
                    (encode-coding-string host-key 'utf-8 t)
                    nil nil t)))
              (unless (and (>= (length plaintext) (length domain-hash))
                           (string-prefix-p domain-hash plaintext))
                (error "browser-cookies: Chromium domain binding failed"))
              (setq plaintext (substring plaintext (length domain-hash)))))
          (decode-coding-string plaintext 'utf-8 t))
      (error
       (error "browser-cookies: Chromium decryption failed: %s"
              (error-message-string decrypt-error))))))

(defun browser-cookies--chromium-time-to-unix (value)
  "Convert Chromium microsecond timestamp VALUE to Unix seconds."
  (/ (- value browser-cookies--chromium-time-epoch-offset) 1000000.0))

(defun browser-cookies--select-chromium (database schema url spec)
  "Select and decrypt cookies for URL from Chromium DATABASE and SCHEMA."
  (pcase-let* ((`(,host ,request-path ,request-secure)
                 (browser-cookies--url-parts url))
               (domains (browser-cookies--domain-candidates host))
               (placeholders (mapconcat (lambda (_domain) "?") domains ","))
               (version-row
                (car (sqlite-select
                      database
                      (concat "SELECT value FROM " schema
                              ".meta WHERE key = ?")
                      (list "version"))))
               (database-version
                (and version-row
                     (string-to-number (format "%s" (car version-row)))))
               (now (float-time))
               (raw-rows
                (sqlite-select
                 database
                 (concat
                  "SELECT host_key, name, value, encrypted_value, path, "
                  "expires_utc, is_secure, has_expires, creation_utc FROM "
                  schema ".cookies WHERE top_frame_site_key = ? "
                  "AND host_key IN (" placeholders ")")
                 (cons "" domains)))
               (rows
                (cl-remove-if-not
                 (lambda (row)
                   (let* ((host-key (nth 0 row))
                          (cookie-path (or (nth 4 row) "/"))
                          (expires-utc (nth 5 row))
                          (cookie-secure (not (zerop (or (nth 6 row) 0))))
                          (has-expires (not (zerop (or (nth 7 row) 0))))
                          (expires
                           (and has-expires
                                (numberp expires-utc)
                                (browser-cookies--chromium-time-to-unix
                                 expires-utc))))
                     (and
                      (browser-cookies--domain-matches-p host-key host)
                      (browser-cookies--path-matches-p
                       cookie-path request-path)
                      (or (not cookie-secure) request-secure)
                      (or (not has-expires)
                          (and expires (> expires now))))))
                 raw-rows)))
    (unless (and (integerp database-version) (> database-version 0))
      (error "browser-cookies: invalid Chromium schema version"))
    (let ((prefixes
           (delete-dups
            (delq nil
                  (mapcar
                   (lambda (row)
                     (let ((plain (nth 2 row))
                           (encrypted (nth 3 row)))
                       (and (string-empty-p (or plain ""))
                            (stringp encrypted)
                            (>= (length encrypted) 3)
                            (substring encrypted 0 3))))
                   rows))))
          keys records)
      (unwind-protect
          (progn
            (dolist (prefix prefixes)
              (push
               (cons prefix
                     (pcase prefix
                       ("v10" (browser-cookies--chromium-v10-key))
                       ("v11" (browser-cookies--chromium-v11-key spec))
                       (_ (error
                           "browser-cookies: unsupported Chromium encryption: %s"
                           prefix))))
               keys))
            (dolist (row rows)
              (let* ((host-key (nth 0 row))
                     (plain-value (nth 2 row))
                     (encrypted-value (nth 3 row))
                     (expires-utc (nth 5 row))
                     (has-expires (not (zerop (or (nth 7 row) 0))))
                     (value
                      (cond
                       ((not (string-empty-p (or plain-value ""))) plain-value)
                       ((not (string-empty-p (or encrypted-value "")))
                        (browser-cookies--chromium-decrypt-cookie
                         encrypted-value host-key database-version keys))
                       (t ""))))
                (push
                 (browser-cookies--make-record
                  :name (nth 1 row)
                  :value value
                  :domain host-key
                  :path (or (nth 4 row) "/")
                  :expires
                  (and has-expires (numberp expires-utc)
                       (browser-cookies--chromium-time-to-unix expires-utc))
                  :secure (not (zerop (or (nth 6 row) 0)))
                  :creation (nth 8 row))
                 records)))
            (browser-cookies--records-to-alist records))
        (dolist (entry keys)
          (when (stringp (cdr entry))
            (clear-string (cdr entry))))))))

(defun browser-cookies--read-chromium (path url browser)
  "Read cookies for URL from BROWSER's Chromium database PATH."
  (let ((spec (browser-cookies--chromium-browser-spec browser)))
    (browser-cookies--query-database
     path
     (lambda (database schema)
       (browser-cookies--select-chromium database schema url spec)))))

;;;###autoload
(cl-defun browser-cookies-get
    (url &key
         (browser browser-cookies-browser)
         (profile-directory browser-cookies-profile-directory)
         (origin-attributes browser-cookies-firefox-origin-attributes))
  "Return browser cookies applicable to URL as ((NAME . VALUE) ...).

BROWSER and PROFILE-DIRECTORY default to the corresponding customization
variables.  ORIGIN-ATTRIBUTES selects an exact Firefox container context."
  (let ((path (browser-cookies--store-file browser profile-directory)))
    (pcase browser
      ('firefox (browser-cookies--read-firefox path url origin-attributes))
      ((or 'chromium 'chrome 'edge)
       (browser-cookies--read-chromium path url browser))
      (_ (error "browser-cookies: unsupported browser: %S" browser)))))

;;;###autoload
(cl-defun browser-cookies-header (url &rest arguments)
  "Return a Cookie request header value for URL.

ARGUMENTS are forwarded to `browser-cookies-get'.  Return nil when no cookie
applies to URL."
  (when-let* ((cookies (apply #'browser-cookies-get url arguments)))
    (mapconcat (lambda (cookie)
                 (format "%s=%s" (car cookie) (cdr cookie)))
               cookies "; ")))

(provide 'browser-cookies)
;;; browser-cookies.el ends here
