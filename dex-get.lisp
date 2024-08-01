;;;; dex-get.lisp 

(in-package #:dex-get)

(defparameter *user-agent* "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0")

(defstruct (dexans (:type list) :named)
  ;; a value of t for error means that body is sexp. Otherwise it is the html text
  body status-code headers uri host http-stream must-close status-text err)

(defun dex-good (dexa)
  (and (equal 200 (dexans-status-code dexa))
	   (not (dexans-err dexa))))

(defun other-check-ip (host)
  (handler-case 
	  (let ((adr (multiple-value-list (ensure-hostname host :errorp nil))))
		(unless (first adr)
		  (xlogntf "oci: error eh ~s: apparently no such host as ~a" adr host))
		(first adr))
	(error (d)
	  (progn
		;;(break "wtf")
		(xlogf "oci: error ~a: ~%no such host as ~a" d host)
		nil))))

(defun chk-ip-addr (host)
  (let ((ip-addr
		   (handler-case 
			   (let ((adr (lookup-hostname host)))
				 adr)
			 (error (d)
			   (progn
				 (xlogf "cia: error ~a: ~%no such host as ~a" d host)
				 nil)))))
	ip-addr))

(defparameter *resulting-condition* 3)

(defun dex-get (fetch-this &key (timeout 13) (binary nil) (content-enc nil))
  (let* ((headers
		   `(("User-Agent" . ,*user-agent*) 
			 ("Accept" . "text/html,application/xhtml+xml,application/xml;q=0.9,image/jpg,image/jpeg,image/avif,image/webp,*/*;q=0.8")
			 ("Accept-Encoding" . "gzip, deflate") ;; see decompress-body--no brotli
			 ("Accept-language" . "en-US,en;q=0.5")
			 ("Connection" . "keep-alive"))))
	(if content-enc
		(setf headers (append headers (list `("Content-Encoding" . "gzip")))))
	(handler-case
		(let ((host (uri-host (uri fetch-this))))
		  (multiple-value-bind (body status-code headers uri http-stream must-close status-text)
			  (sb-sys:with-deadline  (:seconds timeout)
				(dex:get fetch-this
						 :headers
						 headers
						 :connect-timeout 5 :read-timeout 5 :force-binary `,binary :force-string t :use-connection-pool nil :keep-alive nil :read-timeout 10))
			(make-dexans  :body body  :status-code status-code :headers headers :uri uri 
						  :http-stream http-stream :must-close must-close  :status-text status-text :host host :err nil)))
	  (quri.error:uri-invalid-port(e)
		(let ((ans (make-dexans :body '(:not-html :ssl :uri-port-error) :status-code 500 :status-text :uri-error :err t)))
		  (xlogf "~e for ~a: bad port found; error status ~s " e fetch-this (dexans-err ans) )))
	  (SB-SYS:DEADLINE-TIMEOUT (e)
		(xlogf "~e for ~a " e fetch-this)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text "website-timeout" :err t))
	  (SB-BSD-SOCKETS:TRY-AGAIN-ERROR (te)
		(xlogf "dg: sb-bsd-sockets:try-again-error busted http request for ~a~%~a" fetch-this te)
		(make-dexans :body '(:not-html :try-again failure) :status-code 500 :status-text "website-timeout" :err t))
	  (USOCKET:TIMEOUT-ERROR (te)
		(xlogf "dg:usocket:timeout-error: busted http request for ~a~%~a" fetch-this te)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text "website-timeout" :err t))
	  (USOCKET:CONNECTION-REFUSED-ERROR (er)
		(xlogf "dg:USOCKET:CONNECTION-REFUSED-ERROR: busted http request for ~a~%~a" fetch-this er)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text :connection-refused :err t))
	  (CL+SSL::SSL-ERROR (hah)
		(xlogf "dg:cl+ssl::ssl-error: busted http request for ~a~%~a" fetch-this hah)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text "ssl error" :err t)) 
	  (FAST-HTTP.ERROR:INVALID-CONTENT-LENGTH (q)
		(xlogf "dg:fast-http.error:invalid-content-length: busted http request for ~a~%~a" fetch-this q)
		(make-dexans :body '(:not-html :ssl invalid-client-length) :status-code 500 :status-text :connection-refused :err t))
	  (CL+SSL::SSL-ERROR (q)
		(xlogft "dg: cl+ssl::ssl-error: busted http request for ~a~%~a" fetch-this  q)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text q :err t))
	  (http-request-failed (j)
		(setf *resulting-condition* j)
		(xlogf "dg: http-request-failed for ~s ~%body type ~s" fetch-this (type-of j))
		(make-dexans :body (response-body j) :status-code (response-status j) :status-text "Bad request" :headers (response-headers j) :err t))
	  (USOCKET:NS-HOST-NOT-FOUND-ERROR (hnf)
		(xlogf "dg: host not found error fetch-this is ~a host ~A" fetch-this hnf)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text hnf  :err t))
	  (HTTP-REQUEST-NOT-FOUND (e)
		(xlogntf "dg: error: not found ~a, for ~a"  fetch-this e)
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text e  :err t))
	  (error (e)
		(xlogntf "dg: error: general ~a for ~a" fetch-this  (type-of e))
		(make-dexans :body '(:not-html :ssl failure) :status-code 500 :status-text e  :err t)))))

(defun write-headers-from-dexans (dexa fo)
  (let ((hdr-path fo))
	(with-open-file (hdrfo hdr-path 
						   :if-exists :append
						   :if-does-not-exist :create
						   :direction :output
						   :element-type 'character
						   :external-format  :utf-8)
      (if (dexans-headers dexa)
		  (maphash #'(lambda (k v)
                   (write-line (format nil "~a=~a" k v) hdrfo))
               (dexans-headers dexa))
		  (xlogntf "Sorry, EIAINTGOTNO headers"))
      (write-line "----------------------------------------" hdrfo)
      (write-line (format nil "status code ~A" (dexans-status-code dexa)) hdrfo)
      (write-line (format nil "status-text ~A" (dexans-status-text dexa)) hdrfo))))

(defun write-sxp (fileo sxp)
  (with-open-file (fo fileo  :direction :output :if-exists :supersede :if-does-not-exist :create)
	(write sxp :stream fo)))

