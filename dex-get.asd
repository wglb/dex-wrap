;;;; dex-get.asd

(asdf:defsystem #:dex-get
  :description "Wrapper for dexador"
  :author "wglb (wgl@ciex-security.com)"
  :license  "GNU public v3"
  :version "1.1.6"
  :serial t
  :depends-on (#:quri #:dexador #:iolib/sockets #:cl-html-parse #:xlog)
  :components ((:file "dex-get-pkg")
               (:file "dex-get")))
