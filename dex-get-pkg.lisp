;;;; package.lisp

(defpackage #:dex-get
  (:use #:cl
		#:quri
		#:dexador
		#:iolib/sockets
		#:cl-html-parse
		#:xlog)
  (:export #:dexans
		   #:dex-get
		   #:dex-good
		   #:dexans-err
		   #:dexans-body
		   #:write-headers-from-dexans
		   #:write-sxp
		   #:dexans-uri
		   #:dexans-status-code
		   #:dexans-status-text
		   #:dexans-headers
		   #:pull-web-page)
  (:shadowing-import-from :dex
   :get :delete))
