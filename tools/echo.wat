;; echo — the reference tool, and the executable definition of the tool ABI.
;;
;; Returns its input unchanged. Imports nothing, which is mandatory: the host
;; linker is empty, so a module declaring any import fails to instantiate.
;;
;; ABI:
;;   memory                    exported linear memory
;;   alloc(n) -> ptr           reserve n bytes
;;   run(ptr, len) -> packed   (ptr << 32) | len of the output
;;
;; The allocator is a bump pointer that never frees. That is correct here, not
;; lazy: a `Store` lives for exactly one call and its whole linear memory is
;; dropped afterwards, so reclaiming inside the guest would be work whose only
;; effect is to slow the call down and burn fuel.

(module
  (memory (export "memory") 1)

  ;; First 1 KiB is left alone so a real tool has room for statics.
  (global $next (mut i32) (i32.const 1024))

  (func (export "alloc") (param $n i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $n)))
    (local.get $p))

  (func (export "run") (param $ptr i32) (param $len i32) (result i64)
    ;; The host wrote the input at $ptr, so echoing is just handing the same
    ;; range back. A real tool would allocate an output buffer and return that.
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
