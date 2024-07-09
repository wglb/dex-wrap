;;;; package.lisp

(defpackage #:dex-get
  (:use #:cl
		#:quri
		#:dexador
		#:iolib/sockets
		#:xlog)
  (:export #:dexans
		   #:dex-get
		   #:dex-good
		   #:dexans-body
		   #:write-headers-from-dexans
		   #:write-sxp
		   #:dexans-uri
		   #:dexans-status-code
		   #:dexans-status-text
		   #:dexans-headers)
  (:shadowing-import-from :dex
   :get :delete))
