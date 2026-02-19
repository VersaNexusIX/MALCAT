	.arch	armv8-a+fp+simd
	.text

	.global	asm_compute_entropy
	.global	asm_scan_signature
	.global	asm_parse_pe_magic
	.global	asm_parse_elf_magic
	.global	asm_compute_checksum
	.global	asm_find_pattern
	.global	asm_xor_scan
	.global	asm_suspicious_score
	.global	asm_rot13
	.global	asm_byte_frequency
	.global	asm_count_null_bytes
	.global	asm_detect_nop_sled
	.global	asm_compute_chi2
	.global	asm_find_all_occurrences
	.global	asm_detect_string_table
	.global	asm_count_printable
	.global	asm_longest_run
	.global	asm_compute_adler32
	.global	asm_detect_high_entropy_blocks
	.global	asm_score_obfuscation
	.global	asm_parse_macho_magic
	.global	asm_parse_zip_magic
	.global	asm_detect_xor_key
	.extern log2

	.p2align 2

asm_compute_entropy:
	stp	x29, x30, [sp, #-128]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	d8,  d9,  [sp, #64]
	stp	d10, d11, [sp, #80]

	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	cbz	x1, .Lent_zero

	sub	sp, sp, #1024
	mov	x22, sp
	mov	x23, #256
.Lent_clr:
	sub	x23, x23, #1
	str	wzr, [x22, x23, lsl #2]
	cbnz	x23, .Lent_clr

	mov	x23, #0
.Lent_cnt:
	cmp	x23, x20
	b.ge	.Lent_calc
	ldrb	w24, [x19, x23]
	ldr	w9, [x22, x24, lsl #2]
	add	w9, w9, #1
	str	w9, [x22, x24, lsl #2]
	add	x23, x23, #1
	b	.Lent_cnt

.Lent_calc:
	mov	x23, #0
	ucvtf	d9, x20
	fmov d8, xzr
.Lent_loop:
	cmp	x23, #256
	b.ge	.Lent_write
	ldr	w9, [x22, x23, lsl #2]
	cbz	w9, .Lent_skip
	ucvtf  d10, w9
  fdiv   d10, d10, d9 
  fmov   d0, d10
  bl     log2 
  fmul   d0, d0, d10
  fsub   d8, d8, d0
.Lent_skip:
	add	x23, x23, #1
	b	.Lent_loop

.Lent_write:
	add	sp, sp, #1024
	cbz	x21, .Lent_ok
	str	d8, [x21]
.Lent_ok:
	mov	x0, #0
	b	.Lent_ret
.Lent_zero:
	mov	x0, #-1
.Lent_ret:
	ldp	d10, d11, [sp, #80]
	ldp	d8,  d9,  [sp, #64]
	ldp	x23, x24, [sp, #48]
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #128
	ret

asm_byte_frequency:
	stp	x29, x30, [sp, #-32]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	mov	x19, x0
	mov	x20, x1
	cbz	x2, .Lfreq_ret
	mov	x3, x2
	mov	x4, #256
.Lfreq_clr:
	sub	x4, x4, #1
	str	wzr, [x3, x4, lsl #2]
	cbnz	x4, .Lfreq_clr
	mov	x4, #0
.Lfreq_loop:
	cmp	x4, x20
	b.ge	.Lfreq_ret
	ldrb	w5, [x19, x4]
	ldr	w6, [x3, x5, lsl #2]
	add	w6, w6, #1
	str	w6, [x3, x5, lsl #2]
	add	x4, x4, #1
	b	.Lfreq_loop
.Lfreq_ret:
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret

asm_scan_signature:
	stp	x29, x30, [sp, #-48]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	cbz	x22, .Lsig_notfound
	cmp	x22, x20
	b.gt	.Lsig_notfound
	mov	x9, #0
.Lsig_outer:
	sub	x10, x20, x22
	cmp	x9, x10
	b.gt	.Lsig_notfound
	mov	x11, #0
.Lsig_inner:
	cmp	x11, x22
	b.ge	.Lsig_found
	ldrb	w12, [x19, x9]
	ldrb	w13, [x21, x11]
	cmp	w12, w13
	b.ne	.Lsig_mismatch
	add	x9, x9, #1
	add	x11, x11, #1
	b	.Lsig_inner
.Lsig_mismatch:
	sub	x9, x9, x11
	add	x9, x9, #1
	b	.Lsig_outer
.Lsig_found:
	sub	x0, x9, x22
	b	.Lsig_ret
.Lsig_notfound:
	mov	x0, #-1
.Lsig_ret:
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #48
	ret

asm_find_all_occurrences:
	stp	x29, x30, [sp, #-64]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x23, x4
	mov	x24, x5
	cbz	x22, .Lfall_done
	cmp	x22, x20
	b.gt	.Lfall_done
	mov	x9, #0
	mov	x10, #0
.Lfall_outer:
	sub	x11, x20, x22
	cmp	x9, x11
	b.gt	.Lfall_done
	cmp	x10, x24
	b.ge	.Lfall_done
	mov	x12, #0
.Lfall_inner:
	cmp	x12, x22
	b.ge	.Lfall_hit
	add	x13, x9, x12
	ldrb	w14, [x19, x13]
	ldrb	w15, [x21, x12]
	cmp	w14, w15
	b.ne	.Lfall_miss
	add	x12, x12, #1
	b	.Lfall_inner
.Lfall_hit:
	str	x9, [x23, x10, lsl #3]
	add	x10, x10, #1
	add	x9, x9, #1
	b	.Lfall_outer
.Lfall_miss:
	add	x9, x9, #1
	b	.Lfall_outer
.Lfall_done:
	mov	x0, x10
	ldp	x23, x24, [sp, #48]
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #64
	ret

asm_parse_pe_magic:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	cbz	x0, .Lpe_bad
	cbz	x1, .Lpe_bad
	cmp	x2, #64
	b.lt	.Lpe_bad
	ldrb	w3, [x0]
	cmp	w3, #0x4D
	b.ne	.Lpe_bad
	ldrb	w3, [x0, #1]
	cmp	w3, #0x5A
	b.ne	.Lpe_bad
	ldr	w4, [x0, #0x3C]
	cmp	w4, #0x200
	b.gt	.Lpe_bad
	add	x5, x0, x4
	ldr	w6, [x5]
	mov	w7, #0x4550
	cmp	w6, w7
	b.ne	.Lpe_bad
	ldrh	w8, [x5, #4]
	str	w8, [x1]
	ldr	w8, [x5, #8]
	str	w8, [x1, #4]
	ldrh	w8, [x5, #20]
	str	w8, [x1, #8]
	ldrh	w8, [x5, #22]
	str	w8, [x1, #12]
	ldrh	w9, [x5, #24]
	cmp	w9, #0x10B
	b.eq	.Lpe_pe32
	cmp	w9, #0x20B
	b.eq	.Lpe_pe64
	b	.Lpe_bad
.Lpe_pe32:
	ldrh	w8, [x5, #0x44]
	str	w8, [x1, #16]
	ldr	w8, [x5, #0x60]
	str	w8, [x1, #20]
	mov	w8, #32
	str	w8, [x1, #24]
	b	.Lpe_ok
.Lpe_pe64:
	ldrh	w8, [x5, #0x44]
	str	w8, [x1, #16]
	ldr	w8, [x5, #0x70]
	str	w8, [x1, #20]
	mov	w8, #64
	str	w8, [x1, #24]
.Lpe_ok:
	mov	x0, #1
	b	.Lpe_ret
.Lpe_bad:
	mov	x0, #0
.Lpe_ret:
	ldp	x29, x30, [sp], #16
	ret

asm_parse_elf_magic:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	cbz	x0, .Lelf_bad
	cbz	x2, .Lelf_bad
	cmp	x1, #64
	b.lt	.Lelf_bad
	ldrb	w3, [x0]
	cmp	w3, #0x7F
	b.ne	.Lelf_bad
	ldrb	w3, [x0, #1]
	cmp	w3, #0x45
	b.ne	.Lelf_bad
	ldrb	w3, [x0, #2]
	cmp	w3, #0x4C
	b.ne	.Lelf_bad
	ldrb	w3, [x0, #3]
	cmp	w3, #0x46
	b.ne	.Lelf_bad
	ldrb	w4, [x0, #4]
	str	w4, [x2]
	ldrb	w5, [x0, #5]
	str	w5, [x2, #4]
	ldrh	w6, [x0, #16]
	str	w6, [x2, #8]
	ldrh	w7, [x0, #18]
	str	w7, [x2, #12]
	cmp	w4, #2
	b.ne	.Lelf_32
	ldrh	w8, [x0, #60]
	str	w8, [x2, #16]
	b	.Lelf_ok
.Lelf_32:
	ldrh	w8, [x0, #48]
	str	w8, [x2, #16]
.Lelf_ok:
	mov	x0, #1
	b	.Lelf_ret
.Lelf_bad:
	mov	x0, #0
.Lelf_ret:
	ldp	x29, x30, [sp], #16
	ret

asm_parse_macho_magic:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	cbz	x0, .Lmacho_bad
	cmp	x1, #4
	b.lt	.Lmacho_bad
	ldr	w3, [x0]
	mov	w4, #0xFACE
	movk	w4, #0xFEED, lsl #16
	cmp	w3, w4
	b.eq	.Lmacho_hit
	mov	w4, #0xEDFE
	movk	w4, #0xCEFA, lsl #16
	cmp	w3, w4
	b.eq	.Lmacho_hit
	mov	w4, #0xFACF
	movk	w4, #0xFEED, lsl #16
	cmp	w3, w4
	b.eq	.Lmacho_hit
	mov	w4, #0xEDFE
	movk	w4, #0xCFFA, lsl #16
	cmp	w3, w4
	b.eq	.Lmacho_hit
	mov	w4, #0xBABE
	movk	w4, #0xCAFE, lsl #16
	cmp	w3, w4
	b.eq	.Lmacho_hit
	b	.Lmacho_bad
.Lmacho_hit:
	cbz	x2, .Lmacho_ok
	str	w3, [x2]
.Lmacho_ok:
	mov	x0, #1
	b	.Lmacho_ret
.Lmacho_bad:
	mov	x0, #0
.Lmacho_ret:
	ldp	x29, x30, [sp], #16
	ret

asm_parse_zip_magic:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	cbz	x0, .Lzip_bad
	cmp	x1, #4
	b.lt	.Lzip_bad
	ldrb	w3, [x0]
	cmp	w3, #0x50
	b.ne	.Lzip_bad
	ldrb	w3, [x0, #1]
	cmp	w3, #0x4B
	b.ne	.Lzip_bad
	ldrb	w4, [x0, #2]
	ldrb	w5, [x0, #3]
	cbz	x2, .Lzip_ok
	strb	w4, [x2]
	strb	w5, [x2, #1]
.Lzip_ok:
	mov	x0, #1
	b	.Lzip_ret
.Lzip_bad:
	mov	x0, #0
.Lzip_ret:
	ldp	x29, x30, [sp], #16
	ret

asm_compute_checksum:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x2, #0
	mov	x3, #0
	cbz	x1, .Lck_done
.Lck_loop:
	cmp	x3, x1
	b.ge	.Lck_done
	ldrb	w4, [x0, x3]
	add	x2, x2, x4
	add	x3, x3, #1
	b	.Lck_loop
.Lck_done:
	and	x0, x2, #0xFFFFFFFF
	ldp	x29, x30, [sp], #16
	ret

asm_compute_adler32:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	w2, #1
	mov	w3, #0
	mov	x4, #0
	mov	w5, #65521
	cbz	x1, .Ladler_done
.Ladler_loop:
	cmp	x4, x1
	b.ge	.Ladler_done
	ldrb	w6, [x0, x4]
	add	w2, w2, w6
	udiv	w7, w2, w5
	msub	w2, w7, w5, w2
	add	w3, w3, w2
	udiv	w7, w3, w5
	msub	w3, w7, w5, w3
	add	x4, x4, #1
	b	.Ladler_loop
.Ladler_done:
	lsl	w3, w3, #16
	orr	w0, w3, w2
	ldp	x29, x30, [sp], #16
	ret

asm_count_null_bytes:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x2, #0
	mov	x3, #0
	cbz	x1, .Lnull_done
.Lnull_loop:
	cmp	x3, x1
	b.ge	.Lnull_done
	ldrb	w4, [x0, x3]
	cbnz	w4, .Lnull_skip
	add	x2, x2, #1
.Lnull_skip:
	add	x3, x3, #1
	b	.Lnull_loop
.Lnull_done:
	mov	x0, x2
	ldp	x29, x30, [sp], #16
	ret

asm_count_printable:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x2, #0
	mov	x3, #0
	cbz	x1, .Lprn_done
.Lprn_loop:
	cmp	x3, x1
	b.ge	.Lprn_done
	ldrb	w4, [x0, x3]
	cmp	w4, #0x20
	b.lt	.Lprn_skip
	cmp	w4, #0x7E
	b.gt	.Lprn_skip
	add	x2, x2, #1
.Lprn_skip:
	add	x3, x3, #1
	b	.Lprn_loop
.Lprn_done:
	mov	x0, x2
	ldp	x29, x30, [sp], #16
	ret

asm_detect_nop_sled:
	stp	x29, x30, [sp, #-32]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	mov	x19, x0
	mov	x20, x1
	mov	x4,  x2
	mov	x5,  #0
	mov	x6,  #0
	mov	x7,  #-1
	cbz	x4, .Lnop_done
.Lnop_loop:
	cmp	x5, x20
	b.ge	.Lnop_done
	ldrb	w8, [x19, x5]
	cmp w8, #0x90
  b.eq .Lnop_inc
  mov x6, #0
  add x5, x5, #1
  b .Lnop_loop
.Lnop_inc:
	add	x6, x6, #1
	cmp	x6, x4
	b.lt	.Lnop_cont
	sub	x7, x5, x6
	add	x7, x7, #1
.Lnop_cont:
	add	x5, x5, #1
	b	.Lnop_loop
.Lnop_done:
	mov	x0, x7
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret

asm_suspicious_score:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x2, #0
	mov	x3, #0
	cbz	x1, .Lsus_done
.Lsus_loop:
	cmp	x3, x1
	b.ge	.Lsus_done
	ldrb	w4, [x0, x3]
	cmp	w4, #0x90
	b.eq	.Lsus_nop
	cmp	w4, #0xCC
	b.eq	.Lsus_int3
	cmp	w4, #0xEB
	b.eq	.Lsus_jmps
	cmp	w4, #0xE8
	b.eq	.Lsus_call
	b	.Lsus_cont
.Lsus_nop:
	add	x2, x2, #4
	b	.Lsus_cont
.Lsus_int3:
	add	x2, x2, #12
	b	.Lsus_cont
.Lsus_jmps:
	add	x2, x2, #1
	b	.Lsus_cont
.Lsus_call:
	add	x2, x2, #1
.Lsus_cont:
	add	x3, x3, #1
	b	.Lsus_loop
.Lsus_done:
	mov	x0, x2
	ldp	x29, x30, [sp], #16
	ret

asm_xor_scan:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x3, #0
	mov	x4, #0
	cbz	x1, .Lxor_done
.Lxor_loop:
	cmp	x4, x1
	b.ge	.Lxor_done
	ldrb	w5, [x0, x4]
	eor	w5, w5, w2
	add	x3, x3, x5
	add	x4, x4, #1
	b	.Lxor_loop
.Lxor_done:
	mov	x0, x3
	ldp	x29, x30, [sp], #16
	ret

asm_detect_xor_key:
	stp	x29, x30, [sp, #-64]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, #0
	mov	x23, #0
	mov	x24, #0
.Lxork_key:
	cmp	x24, #256
	b.ge	.Lxork_done
	mov	x3, #0
	mov	x4, #0
.Lxork_byte:
	cmp	x4, x20
	b.ge	.Lxork_check
	ldrb	w5, [x19, x4]
	eor	w5, w5, w24
	cmp	w5, #0x20
	b.lt	.Lxork_np
	cmp	w5, #0x7E
	b.gt	.Lxork_np
	add	x3, x3, #1
.Lxork_np:
	add	x4, x4, #1
	b	.Lxork_byte
.Lxork_check:
	cmp	x3, x22
	b.le	.Lxork_next
	mov	x22, x3
	mov	x23, x24
.Lxork_next:
	add	x24, x24, #1
	b	.Lxork_key
.Lxork_done:
	cbz	x21, .Lxork_ret
	strb	w23, [x21]
.Lxork_ret:
	mov	x0, x22
	ldp	x23, x24, [sp, #48]
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #64
	ret

asm_longest_run:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x3, #0
	mov	x4, #0
	mov	x5, #0
	cbz	x1, .Lrun_done
.Lrun_loop:
	cmp	x4, x1
	b.ge	.Lrun_done
	ldrb	w6, [x0, x4]
	cmp	w6, w2
	b.ne	.Lrun_reset
	add	x5, x5, #1
	cmp	x5, x3
	b.le	.Lrun_next
	mov	x3, x5
	b	.Lrun_next
.Lrun_reset:
	mov	x5, #0
.Lrun_next:
	add	x4, x4, #1
	b	.Lrun_loop
.Lrun_done:
	mov	x0, x3
	ldp	x29, x30, [sp], #16
	ret

asm_detect_high_entropy_blocks:
	stp	x29, x30, [sp, #-64]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x23, x4
	mov	x24, #0
	mov	x9,  #0
	cbz	x21, .Lheb_done
	cbz	x22, .Lheb_done
	cbz	x23, .Lheb_done
.Lheb_block:
	cmp	x9, x20
	b.ge	.Lheb_done
	cmp	x24, x23
	b.ge	.Lheb_done
	sub	sp, sp, #256
	mov	x10, sp
	mov	x11, #256
.Lheb_clr:
	sub	x11, x11, #1
	strb	wzr, [x10, x11]
	cbnz	x11, .Lheb_clr
	add	x12, x9, x21
	cmp	x12, x20
	csel	x12, x12, x20, lt
	mov	x13, x9
	mov	x14, #0
.Lheb_scan:
	cmp	x13, x12
	b.ge	.Lheb_eval
	ldrb	w15, [x19, x13]
	ldrb	w16, [x10, x15]
	cbnz	w16, .Lheb_scip
	mov	w16, #1
	strb	w16, [x10, x15]
	add	x14, x14, #1
.Lheb_scip:
	add	x13, x13, #1
	b	.Lheb_scan
.Lheb_eval:
	add	sp, sp, #256
	cmp	x14, #250
	b.lt	.Lheb_next
	str	x9, [x22, x24, lsl #3]
	add	x24, x24, #1
.Lheb_next:
	add	x9, x9, x21
	b	.Lheb_block
.Lheb_done:
	mov	x0, x24
	ldp	x23, x24, [sp, #48]
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #64
	ret

asm_score_obfuscation:
	stp	x29, x30, [sp, #-96]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	str	x27,      [sp, #80]
	mov	x19, x0
	mov	x20, x1
	mov	x21, #0
	mov	x22, #0
	mov	x23, #0
	mov	x24, #0
	cbz	x20, .Lobs_zero
	sub	sp, sp, #1024
	mov	x26, sp
	mov	x27, #256
.Lobs_clr:
	sub	x27, x27, #1
	str	wzr, [x26, x27, lsl #2]
	cbnz	x27, .Lobs_clr
	mov	x3, #0
.Lobs_scan:
	cmp	x3, x20
	b.ge	.Lobs_calc
	ldrb	w4, [x19, x3]
	cbnz	w4, .Lobs_nnull
	add	x21, x21, #1
.Lobs_nnull:
	cmp	w4, #0x20
	b.lt	.Lobs_np
	cmp	w4, #0x7E
	b.gt	.Lobs_np
	add	x22, x22, #1
.Lobs_np:
	cmp	w4, #0x90
	b.eq	.Lobs_sop
	cmp	w4, #0xCC
	b.eq	.Lobs_sop
	cmp	w4, #0xEB
	b.ne	.Lobs_nosop
.Lobs_sop:
	add	x23, x23, #1
.Lobs_nosop:
	ldr	w5, [x26, x4, lsl #2]
	add	w5, w5, #1
	str	w5, [x26, x4, lsl #2]
	add	x3, x3, #1
	b	.Lobs_scan
.Lobs_calc:
	mov	x27, #0
	mov	x24, #0
.Lobs_uniq:
	cmp	x27, #256
	b.ge	.Lobs_score
	ldr	w5, [x26, x27, lsl #2]
	cbz	w5, .Lobs_unskip
	add	x24, x24, #1
.Lobs_unskip:
	add	x27, x27, #1
	b	.Lobs_uniq
.Lobs_score:
	add	sp, sp, #1024
	mov	x0, #0
	lsl	x3, x21, #8
	udiv	x3, x3, x20
	cmp	x3, #200
	csel	x3, x3, xzr, lt
	add	x0, x0, x3
	lsl	x3, x22, #8
	udiv	x3, x3, x20
	mov	x4, #120
	sub	x3, x4, x3
	cmp	x3, #0
	csel	x3, x3, xzr, ge
	cmp	x3, #200
	mov	x4, #120
	csel	x3, x3, x4, lt
	add	x0, x0, x3
	mov	x3, #300
	lsl	x4, x23, #4
	cmp	x4, x3
	csel	x4, x4, x3, lt
	add	x0, x0, x4
	cmp	x24, #220
	mov	x3, #30
	csel	x4, x3, xzr, gt
	add	x0, x0, x4
	mov	x3, #1000
	cmp	x0, x3
	csel	x0, x0, x3, lt
	b	.Lobs_ret
.Lobs_zero:
	mov	x0, #0
.Lobs_ret:
	ldr	x27,      [sp, #80]
	ldp	x25, x26, [sp, #64]
	ldp	x23, x24, [sp, #48]
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #96
	ret

asm_detect_string_table:
	stp	x29, x30, [sp, #-48]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x9,  #0
	mov	x10, #0
	mov	x11, #0
	mov	x12, #-1
.Lst_loop:
	cmp	x9, x20
	b.ge	.Lst_done
	ldrb	w13, [x19, x9]
	cmp	w13, #0x20
	b.lt	.Lst_nonprint
	cmp	w13, #0x7E
	b.le	.Lst_print
.Lst_nonprint:
	cmp	x10, x21
	b.lt	.Lst_reset
	add	x11, x11, #1
	cmp	x11, #5
	b.lt	.Lst_mark
	mov	x12, x9
	cbz	x22, .Lst_mark
	str	x11, [x22]
.Lst_mark:
	mov	x10, #0
	b	.Lst_next
.Lst_reset:
	mov	x10, #0
	mov	x11, #0
	b	.Lst_next
.Lst_print:
	add	x10, x10, #1
.Lst_next:
	add	x9, x9, #1
	b	.Lst_loop
.Lst_done:
	mov	x0, x12
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #48
	ret

asm_find_pattern:
	stp	x29, x30, [sp, #-48]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x9,  #0
	mov	x10, #0
.Lfp_loop:
	cmp	x9, x20
	b.ge	.Lfp_done
	ldrb	w11, [x19, x9]
	ldrb	w12, [x21, x10]
	cmp	w11, w12
	b.ne	.Lfp_reset
	add	x10, x10, #1
	cmp	x10, x22
	b.ge	.Lfp_hit
	add	x9, x9, #1
	b	.Lfp_loop
.Lfp_reset:
	cbnz	x10, .Lfp_back
	add	x9, x9, #1
	b	.Lfp_loop
.Lfp_back:
	mov	x10, #0
	b	.Lfp_loop
.Lfp_hit:
	sub	x0, x9, x22
	add	x0, x0, #1
	b	.Lfp_ret
.Lfp_done:
	mov	x0, #-1
.Lfp_ret:
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #48
	ret

asm_rot13:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x2, #0
.Lrot_loop:
	cmp	x2, x1
	b.ge	.Lrot_done
	ldrb	w3, [x0, x2]
	cmp	w3, #0x41
	b.lt	.Lrot_lower
	cmp	w3, #0x5A
	b.gt	.Lrot_lower
	sub	w3, w3, #0x41
	add	w3, w3, #13
	mov	w4, #26
	udiv	w5, w3, w4
	msub	w3, w5, w4, w3
	add	w3, w3, #0x41
	strb	w3, [x0, x2]
	b	.Lrot_next
.Lrot_lower:
	cmp	w3, #0x61
	b.lt	.Lrot_next
	cmp	w3, #0x7A
	b.gt	.Lrot_next
	sub	w3, w3, #0x61
	add	w3, w3, #13
	mov	w4, #26
	udiv	w5, w3, w4
	msub	w3, w5, w4, w3
	add	w3, w3, #0x61
	strb	w3, [x0, x2]
.Lrot_next:
	add	x2, x2, #1
	b	.Lrot_loop
.Lrot_done:
	ldp	x29, x30, [sp], #16
	ret

asm_compute_chi2:
	stp	x29, x30, [sp, #-32]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	mov	x19, x0
	mov	x20, x1
	cbz	x20, .Lchi_zero
	mov	x2, #256
	udiv	x3, x20, x2
	cbz	x3, .Lchi_zero
	mov	x4, #0
	mov	x5, #0
.Lchi_loop:
	cmp	x5, #256
	b.ge	.Lchi_done
	ldr	w6, [x19, x5, lsl #2]
	uxtw	x6, w6
	sub	x7, x6, x3
	mul	x7, x7, x7
	udiv	x8, x7, x3
	add	x4, x4, x8
	add	x5, x5, #1
	b	.Lchi_loop
.Lchi_done:
	mov	x0, x4
	b	.Lchi_ret
.Lchi_zero:
	mov	x0, #0
.Lchi_ret:
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret

	.end

