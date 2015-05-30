.text



.globl	_bn_mul_mont_gather5

.p2align	6
_bn_mul_mont_gather5:
	testl	$7,%r9d
	jnz	L$mul_enter
	movl	_OPENSSL_ia32cap_P+8(%rip),%r11d
	jmp	L$mul4x_enter

.p2align	4
L$mul_enter:
	movl	%r9d,%r9d
	movq	%rsp,%rax
	movl	8(%rsp),%r10d
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	leaq	2(%r9),%r11
	negq	%r11
	leaq	(%rsp,%r11,8),%rsp
	andq	$-1024,%rsp

	movq	%rax,8(%rsp,%r9,8)
L$mul_body:
	movq	%rdx,%r12
	movq	%r10,%r11
	shrq	$3,%r10
	andq	$7,%r11
	notq	%r10
	leaq	L$magic_masks(%rip),%rax
	andq	$3,%r10
	leaq	96(%r12,%r11,8),%r12
	movq	0(%rax,%r10,8),%xmm4
	movq	8(%rax,%r10,8),%xmm5
	movq	16(%rax,%r10,8),%xmm6
	movq	24(%rax,%r10,8),%xmm7

	movq	-96(%r12),%xmm0
	movq	-32(%r12),%xmm1
	pand	%xmm4,%xmm0
	movq	32(%r12),%xmm2
	pand	%xmm5,%xmm1
	movq	96(%r12),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3
	por	%xmm2,%xmm0
	leaq	256(%r12),%r12
	por	%xmm3,%xmm0

.byte	102,72,15,126,195

	movq	(%r8),%r8
	movq	(%rsi),%rax

	xorq	%r14,%r14
	xorq	%r15,%r15

	movq	-96(%r12),%xmm0
	movq	-32(%r12),%xmm1
	pand	%xmm4,%xmm0
	movq	32(%r12),%xmm2
	pand	%xmm5,%xmm1

	movq	%r8,%rbp
	mulq	%rbx
	movq	%rax,%r10
	movq	(%rcx),%rax

	movq	96(%r12),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3

	imulq	%r10,%rbp
	movq	%rdx,%r11

	por	%xmm2,%xmm0
	leaq	256(%r12),%r12
	por	%xmm3,%xmm0

	mulq	%rbp
	addq	%rax,%r10
	movq	8(%rsi),%rax
	adcq	$0,%rdx
	movq	%rdx,%r13

	leaq	1(%r15),%r15
	jmp	L$1st_enter

.p2align	4
L$1st:
	addq	%rax,%r13
	movq	(%rsi,%r15,8),%rax
	adcq	$0,%rdx
	addq	%r11,%r13
	movq	%r10,%r11
	adcq	$0,%rdx
	movq	%r13,-16(%rsp,%r15,8)
	movq	%rdx,%r13

L$1st_enter:
	mulq	%rbx
	addq	%rax,%r11
	movq	(%rcx,%r15,8),%rax
	adcq	$0,%rdx
	leaq	1(%r15),%r15
	movq	%rdx,%r10

	mulq	%rbp
	cmpq	%r9,%r15
	jne	L$1st

.byte	102,72,15,126,195

	addq	%rax,%r13
	movq	(%rsi),%rax
	adcq	$0,%rdx
	addq	%r11,%r13
	adcq	$0,%rdx
	movq	%r13,-16(%rsp,%r15,8)
	movq	%rdx,%r13
	movq	%r10,%r11

	xorq	%rdx,%rdx
	addq	%r11,%r13
	adcq	$0,%rdx
	movq	%r13,-8(%rsp,%r9,8)
	movq	%rdx,(%rsp,%r9,8)

	leaq	1(%r14),%r14
	jmp	L$outer
.p2align	4
L$outer:
	xorq	%r15,%r15
	movq	%r8,%rbp
	movq	(%rsp),%r10

	movq	-96(%r12),%xmm0
	movq	-32(%r12),%xmm1
	pand	%xmm4,%xmm0
	movq	32(%r12),%xmm2
	pand	%xmm5,%xmm1

	mulq	%rbx
	addq	%rax,%r10
	movq	(%rcx),%rax
	adcq	$0,%rdx

	movq	96(%r12),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3

	imulq	%r10,%rbp
	movq	%rdx,%r11

	por	%xmm2,%xmm0
	leaq	256(%r12),%r12
	por	%xmm3,%xmm0

	mulq	%rbp
	addq	%rax,%r10
	movq	8(%rsi),%rax
	adcq	$0,%rdx
	movq	8(%rsp),%r10
	movq	%rdx,%r13

	leaq	1(%r15),%r15
	jmp	L$inner_enter

.p2align	4
L$inner:
	addq	%rax,%r13
	movq	(%rsi,%r15,8),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	movq	(%rsp,%r15,8),%r10
	adcq	$0,%rdx
	movq	%r13,-16(%rsp,%r15,8)
	movq	%rdx,%r13

L$inner_enter:
	mulq	%rbx
	addq	%rax,%r11
	movq	(%rcx,%r15,8),%rax
	adcq	$0,%rdx
	addq	%r11,%r10
	movq	%rdx,%r11
	adcq	$0,%r11
	leaq	1(%r15),%r15

	mulq	%rbp
	cmpq	%r9,%r15
	jne	L$inner

.byte	102,72,15,126,195

	addq	%rax,%r13
	movq	(%rsi),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	movq	(%rsp,%r15,8),%r10
	adcq	$0,%rdx
	movq	%r13,-16(%rsp,%r15,8)
	movq	%rdx,%r13

	xorq	%rdx,%rdx
	addq	%r11,%r13
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%r13,-8(%rsp,%r9,8)
	movq	%rdx,(%rsp,%r9,8)

	leaq	1(%r14),%r14
	cmpq	%r9,%r14
	jb	L$outer

	xorq	%r14,%r14
	movq	(%rsp),%rax
	leaq	(%rsp),%rsi
	movq	%r9,%r15
	jmp	L$sub
.p2align	4
L$sub:	sbbq	(%rcx,%r14,8),%rax
	movq	%rax,(%rdi,%r14,8)
	movq	8(%rsi,%r14,8),%rax
	leaq	1(%r14),%r14
	decq	%r15
	jnz	L$sub

	sbbq	$0,%rax
	xorq	%r14,%r14
	andq	%rax,%rsi
	notq	%rax
	movq	%rdi,%rcx
	andq	%rax,%rcx
	movq	%r9,%r15
	orq	%rcx,%rsi
.p2align	4
L$copy:
	movq	(%rsi,%r14,8),%rax
	movq	%r14,(%rsp,%r14,8)
	movq	%rax,(%rdi,%r14,8)
	leaq	1(%r14),%r14
	subq	$1,%r15
	jnz	L$copy

	movq	8(%rsp,%r9,8),%rsi
	movq	$1,%rax
	movq	-48(%rsi),%r15
	movq	-40(%rsi),%r14
	movq	-32(%rsi),%r13
	movq	-24(%rsi),%r12
	movq	-16(%rsi),%rbp
	movq	-8(%rsi),%rbx
	leaq	(%rsi),%rsp
L$mul_epilogue:
	.byte	0xf3,0xc3


.p2align	5
bn_mul4x_mont_gather5:
L$mul4x_enter:
	andl	$524544,%r11d
	cmpl	$524544,%r11d
	je	L$mulx4x_enter
.byte	0x67
	movq	%rsp,%rax
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
.byte	0x67
	movl	%r9d,%r10d
	shll	$3,%r9d
	shll	$3+2,%r10d
	negq	%r9








	leaq	-64(%rsp,%r9,2),%r11
	subq	%rsi,%r11
	andq	$4095,%r11
	cmpq	%r11,%r10
	jb	L$mul4xsp_alt
	subq	%r11,%rsp
	leaq	-64(%rsp,%r9,2),%rsp
	jmp	L$mul4xsp_done

.p2align	5
L$mul4xsp_alt:
	leaq	4096-64(,%r9,2),%r10
	leaq	-64(%rsp,%r9,2),%rsp
	subq	%r10,%r11
	movq	$0,%r10
	cmovcq	%r10,%r11
	subq	%r11,%rsp
L$mul4xsp_done:
	andq	$-64,%rsp
	negq	%r9

	movq	%rax,40(%rsp)
L$mul4x_body:

	call	mul4x_internal

	movq	40(%rsp),%rsi
	movq	$1,%rax
	movq	-48(%rsi),%r15
	movq	-40(%rsi),%r14
	movq	-32(%rsi),%r13
	movq	-24(%rsi),%r12
	movq	-16(%rsi),%rbp
	movq	-8(%rsi),%rbx
	leaq	(%rsi),%rsp
L$mul4x_epilogue:
	.byte	0xf3,0xc3



.p2align	5
mul4x_internal:
	shlq	$5,%r9
	movl	8(%rax),%r10d
	leaq	256(%rdx,%r9,1),%r13
	shrq	$5,%r9
	movq	%r10,%r11
	shrq	$3,%r10
	andq	$7,%r11
	notq	%r10
	leaq	L$magic_masks(%rip),%rax
	andq	$3,%r10
	leaq	96(%rdx,%r11,8),%r12
	movq	0(%rax,%r10,8),%xmm4
	movq	8(%rax,%r10,8),%xmm5
	addq	$7,%r11
	movq	16(%rax,%r10,8),%xmm6
	movq	24(%rax,%r10,8),%xmm7
	andq	$7,%r11

	movq	-96(%r12),%xmm0
	leaq	256(%r12),%r14
	movq	-32(%r12),%xmm1
	pand	%xmm4,%xmm0
	movq	32(%r12),%xmm2
	pand	%xmm5,%xmm1
	movq	96(%r12),%xmm3
	pand	%xmm6,%xmm2
.byte	0x67
	por	%xmm1,%xmm0
	movq	-96(%r14),%xmm1
.byte	0x67
	pand	%xmm7,%xmm3
.byte	0x67
	por	%xmm2,%xmm0
	movq	-32(%r14),%xmm2
.byte	0x67
	pand	%xmm4,%xmm1
.byte	0x67
	por	%xmm3,%xmm0
	movq	32(%r14),%xmm3

.byte	102,72,15,126,195
	movq	96(%r14),%xmm0
	movq	%r13,16+8(%rsp)
	movq	%rdi,56+8(%rsp)

	movq	(%r8),%r8
	movq	(%rsi),%rax
	leaq	(%rsi,%r9,1),%rsi
	negq	%r9

	movq	%r8,%rbp
	mulq	%rbx
	movq	%rax,%r10
	movq	(%rcx),%rax

	pand	%xmm5,%xmm2
	pand	%xmm6,%xmm3
	por	%xmm2,%xmm1

	imulq	%r10,%rbp







	leaq	64+8(%rsp,%r11,8),%r14
	movq	%rdx,%r11

	pand	%xmm7,%xmm0
	por	%xmm3,%xmm1
	leaq	512(%r12),%r12
	por	%xmm1,%xmm0

	mulq	%rbp
	addq	%rax,%r10
	movq	8(%rsi,%r9,1),%rax
	adcq	$0,%rdx
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	16(%rcx),%rax
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	16(%rsi,%r9,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	leaq	32(%r9),%r15
	leaq	64(%rcx),%rcx
	adcq	$0,%rdx
	movq	%rdi,(%r14)
	movq	%rdx,%r13
	jmp	L$1st4x

.p2align	5
L$1st4x:
	mulq	%rbx
	addq	%rax,%r10
	movq	-32(%rcx),%rax
	leaq	32(%r14),%r14
	adcq	$0,%rdx
	movq	%rdx,%r11

	mulq	%rbp
	addq	%rax,%r13
	movq	-8(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%r13,-24(%r14)
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	-16(%rcx),%rax
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	adcq	$0,%rdx
	movq	%rdi,-16(%r14)
	movq	%rdx,%r13

	mulq	%rbx
	addq	%rax,%r10
	movq	0(%rcx),%rax
	adcq	$0,%rdx
	movq	%rdx,%r11

	mulq	%rbp
	addq	%rax,%r13
	movq	8(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%r13,-8(%r14)
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	16(%rcx),%rax
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	16(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	leaq	64(%rcx),%rcx
	adcq	$0,%rdx
	movq	%rdi,(%r14)
	movq	%rdx,%r13

	addq	$32,%r15
	jnz	L$1st4x

	mulq	%rbx
	addq	%rax,%r10
	movq	-32(%rcx),%rax
	leaq	32(%r14),%r14
	adcq	$0,%rdx
	movq	%rdx,%r11

	mulq	%rbp
	addq	%rax,%r13
	movq	-8(%rsi),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%r13,-24(%r14)
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	-16(%rcx),%rax
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	(%rsi,%r9,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	adcq	$0,%rdx
	movq	%rdi,-16(%r14)
	movq	%rdx,%r13

.byte	102,72,15,126,195
	leaq	(%rcx,%r9,2),%rcx

	xorq	%rdi,%rdi
	addq	%r10,%r13
	adcq	$0,%rdi
	movq	%r13,-8(%r14)

	jmp	L$outer4x

.p2align	5
L$outer4x:
	movq	(%r14,%r9,1),%r10
	movq	%r8,%rbp
	mulq	%rbx
	addq	%rax,%r10
	movq	(%rcx),%rax
	adcq	$0,%rdx

	movq	-96(%r12),%xmm0
	movq	-32(%r12),%xmm1
	pand	%xmm4,%xmm0
	movq	32(%r12),%xmm2
	pand	%xmm5,%xmm1
	movq	96(%r12),%xmm3

	imulq	%r10,%rbp
.byte	0x67
	movq	%rdx,%r11
	movq	%rdi,(%r14)

	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3
	por	%xmm2,%xmm0
	leaq	(%r14,%r9,1),%r14
	leaq	256(%r12),%r12
	por	%xmm3,%xmm0

	mulq	%rbp
	addq	%rax,%r10
	movq	8(%rsi,%r9,1),%rax
	adcq	$0,%rdx
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	16(%rcx),%rax
	adcq	$0,%rdx
	addq	8(%r14),%r11
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	16(%rsi,%r9,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	leaq	32(%r9),%r15
	leaq	64(%rcx),%rcx
	adcq	$0,%rdx
	movq	%rdx,%r13
	jmp	L$inner4x

.p2align	5
L$inner4x:
	mulq	%rbx
	addq	%rax,%r10
	movq	-32(%rcx),%rax
	adcq	$0,%rdx
	addq	16(%r14),%r10
	leaq	32(%r14),%r14
	adcq	$0,%rdx
	movq	%rdx,%r11

	mulq	%rbp
	addq	%rax,%r13
	movq	-8(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%rdi,-32(%r14)
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	-16(%rcx),%rax
	adcq	$0,%rdx
	addq	-8(%r14),%r11
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	adcq	$0,%rdx
	movq	%r13,-24(%r14)
	movq	%rdx,%r13

	mulq	%rbx
	addq	%rax,%r10
	movq	0(%rcx),%rax
	adcq	$0,%rdx
	addq	(%r14),%r10
	adcq	$0,%rdx
	movq	%rdx,%r11

	mulq	%rbp
	addq	%rax,%r13
	movq	8(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%rdi,-16(%r14)
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	16(%rcx),%rax
	adcq	$0,%rdx
	addq	8(%r14),%r11
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	16(%rsi,%r15,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	leaq	64(%rcx),%rcx
	adcq	$0,%rdx
	movq	%r13,-8(%r14)
	movq	%rdx,%r13

	addq	$32,%r15
	jnz	L$inner4x

	mulq	%rbx
	addq	%rax,%r10
	movq	-32(%rcx),%rax
	adcq	$0,%rdx
	addq	16(%r14),%r10
	leaq	32(%r14),%r14
	adcq	$0,%rdx
	movq	%rdx,%r11

	mulq	%rbp
	addq	%rax,%r13
	movq	-8(%rsi),%rax
	adcq	$0,%rdx
	addq	%r10,%r13
	adcq	$0,%rdx
	movq	%rdi,-32(%r14)
	movq	%rdx,%rdi

	mulq	%rbx
	addq	%rax,%r11
	movq	%rbp,%rax
	movq	-16(%rcx),%rbp
	adcq	$0,%rdx
	addq	-8(%r14),%r11
	adcq	$0,%rdx
	movq	%rdx,%r10

	mulq	%rbp
	addq	%rax,%rdi
	movq	(%rsi,%r9,1),%rax
	adcq	$0,%rdx
	addq	%r11,%rdi
	adcq	$0,%rdx
	movq	%r13,-24(%r14)
	movq	%rdx,%r13

.byte	102,72,15,126,195
	movq	%rdi,-16(%r14)
	leaq	(%rcx,%r9,2),%rcx

	xorq	%rdi,%rdi
	addq	%r10,%r13
	adcq	$0,%rdi
	addq	(%r14),%r13
	adcq	$0,%rdi
	movq	%r13,-8(%r14)

	cmpq	16+8(%rsp),%r12
	jb	L$outer4x
	subq	%r13,%rbp
	adcq	%r15,%r15
	orq	%r15,%rdi
	xorq	$1,%rdi
	leaq	(%r14,%r9,1),%rbx
	leaq	(%rcx,%rdi,8),%rbp
	movq	%r9,%rcx
	sarq	$3+2,%rcx
	movq	56+8(%rsp),%rdi
	jmp	L$sqr4x_sub

.globl	_bn_power5

.p2align	5
_bn_power5:
	movl	_OPENSSL_ia32cap_P+8(%rip),%r11d
	andl	$524544,%r11d
	cmpl	$524544,%r11d
	je	L$powerx5_enter
	movq	%rsp,%rax
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movl	%r9d,%r10d
	shll	$3,%r9d
	shll	$3+2,%r10d
	negq	%r9
	movq	(%r8),%r8







	leaq	-64(%rsp,%r9,2),%r11
	subq	%rsi,%r11
	andq	$4095,%r11
	cmpq	%r11,%r10
	jb	L$pwr_sp_alt
	subq	%r11,%rsp
	leaq	-64(%rsp,%r9,2),%rsp
	jmp	L$pwr_sp_done

.p2align	5
L$pwr_sp_alt:
	leaq	4096-64(,%r9,2),%r10
	leaq	-64(%rsp,%r9,2),%rsp
	subq	%r10,%r11
	movq	$0,%r10
	cmovcq	%r10,%r11
	subq	%r11,%rsp
L$pwr_sp_done:
	andq	$-64,%rsp
	movq	%r9,%r10
	negq	%r9










	movq	%r8,32(%rsp)
	movq	%rax,40(%rsp)
L$power5_body:
.byte	102,72,15,110,207
.byte	102,72,15,110,209
.byte	102,73,15,110,218
.byte	102,72,15,110,226

	call	__bn_sqr8x_internal
	call	__bn_sqr8x_internal
	call	__bn_sqr8x_internal
	call	__bn_sqr8x_internal
	call	__bn_sqr8x_internal

.byte	102,72,15,126,209
.byte	102,72,15,126,226
	movq	%rsi,%rdi
	movq	40(%rsp),%rax
	leaq	32(%rsp),%r8

	call	mul4x_internal

	movq	40(%rsp),%rsi
	movq	$1,%rax
	movq	-48(%rsi),%r15
	movq	-40(%rsi),%r14
	movq	-32(%rsi),%r13
	movq	-24(%rsi),%r12
	movq	-16(%rsi),%rbp
	movq	-8(%rsi),%rbx
	leaq	(%rsi),%rsp
L$power5_epilogue:
	.byte	0xf3,0xc3


.globl	_bn_sqr8x_internal
.private_extern	_bn_sqr8x_internal

.p2align	5
_bn_sqr8x_internal:
__bn_sqr8x_internal:









































































	leaq	32(%r10),%rbp
	leaq	(%rsi,%r9,1),%rsi

	movq	%r9,%rcx


	movq	-32(%rsi,%rbp,1),%r14
	leaq	48+8(%rsp,%r9,2),%rdi
	movq	-24(%rsi,%rbp,1),%rax
	leaq	-32(%rdi,%rbp,1),%rdi
	movq	-16(%rsi,%rbp,1),%rbx
	movq	%rax,%r15

	mulq	%r14
	movq	%rax,%r10
	movq	%rbx,%rax
	movq	%rdx,%r11
	movq	%r10,-24(%rdi,%rbp,1)

	mulq	%r14
	addq	%rax,%r11
	movq	%rbx,%rax
	adcq	$0,%rdx
	movq	%r11,-16(%rdi,%rbp,1)
	movq	%rdx,%r10


	movq	-8(%rsi,%rbp,1),%rbx
	mulq	%r15
	movq	%rax,%r12
	movq	%rbx,%rax
	movq	%rdx,%r13

	leaq	(%rbp),%rcx
	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	movq	%rdx,%r11
	adcq	$0,%r11
	addq	%r12,%r10
	adcq	$0,%r11
	movq	%r10,-8(%rdi,%rcx,1)
	jmp	L$sqr4x_1st

.p2align	5
L$sqr4x_1st:
	movq	(%rsi,%rcx,1),%rbx
	mulq	%r15
	addq	%rax,%r13
	movq	%rbx,%rax
	movq	%rdx,%r12
	adcq	$0,%r12

	mulq	%r14
	addq	%rax,%r11
	movq	%rbx,%rax
	movq	8(%rsi,%rcx,1),%rbx
	movq	%rdx,%r10
	adcq	$0,%r10
	addq	%r13,%r11
	adcq	$0,%r10


	mulq	%r15
	addq	%rax,%r12
	movq	%rbx,%rax
	movq	%r11,(%rdi,%rcx,1)
	movq	%rdx,%r13
	adcq	$0,%r13

	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	movq	16(%rsi,%rcx,1),%rbx
	movq	%rdx,%r11
	adcq	$0,%r11
	addq	%r12,%r10
	adcq	$0,%r11

	mulq	%r15
	addq	%rax,%r13
	movq	%rbx,%rax
	movq	%r10,8(%rdi,%rcx,1)
	movq	%rdx,%r12
	adcq	$0,%r12

	mulq	%r14
	addq	%rax,%r11
	movq	%rbx,%rax
	movq	24(%rsi,%rcx,1),%rbx
	movq	%rdx,%r10
	adcq	$0,%r10
	addq	%r13,%r11
	adcq	$0,%r10


	mulq	%r15
	addq	%rax,%r12
	movq	%rbx,%rax
	movq	%r11,16(%rdi,%rcx,1)
	movq	%rdx,%r13
	adcq	$0,%r13
	leaq	32(%rcx),%rcx

	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	movq	%rdx,%r11
	adcq	$0,%r11
	addq	%r12,%r10
	adcq	$0,%r11
	movq	%r10,-8(%rdi,%rcx,1)

	cmpq	$0,%rcx
	jne	L$sqr4x_1st

	mulq	%r15
	addq	%rax,%r13
	leaq	16(%rbp),%rbp
	adcq	$0,%rdx
	addq	%r11,%r13
	adcq	$0,%rdx

	movq	%r13,(%rdi)
	movq	%rdx,%r12
	movq	%rdx,8(%rdi)
	jmp	L$sqr4x_outer

.p2align	5
L$sqr4x_outer:
	movq	-32(%rsi,%rbp,1),%r14
	leaq	48+8(%rsp,%r9,2),%rdi
	movq	-24(%rsi,%rbp,1),%rax
	leaq	-32(%rdi,%rbp,1),%rdi
	movq	-16(%rsi,%rbp,1),%rbx
	movq	%rax,%r15

	mulq	%r14
	movq	-24(%rdi,%rbp,1),%r10
	addq	%rax,%r10
	movq	%rbx,%rax
	adcq	$0,%rdx
	movq	%r10,-24(%rdi,%rbp,1)
	movq	%rdx,%r11

	mulq	%r14
	addq	%rax,%r11
	movq	%rbx,%rax
	adcq	$0,%rdx
	addq	-16(%rdi,%rbp,1),%r11
	movq	%rdx,%r10
	adcq	$0,%r10
	movq	%r11,-16(%rdi,%rbp,1)

	xorq	%r12,%r12

	movq	-8(%rsi,%rbp,1),%rbx
	mulq	%r15
	addq	%rax,%r12
	movq	%rbx,%rax
	adcq	$0,%rdx
	addq	-8(%rdi,%rbp,1),%r12
	movq	%rdx,%r13
	adcq	$0,%r13

	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	adcq	$0,%rdx
	addq	%r12,%r10
	movq	%rdx,%r11
	adcq	$0,%r11
	movq	%r10,-8(%rdi,%rbp,1)

	leaq	(%rbp),%rcx
	jmp	L$sqr4x_inner

.p2align	5
L$sqr4x_inner:
	movq	(%rsi,%rcx,1),%rbx
	mulq	%r15
	addq	%rax,%r13
	movq	%rbx,%rax
	movq	%rdx,%r12
	adcq	$0,%r12
	addq	(%rdi,%rcx,1),%r13
	adcq	$0,%r12

.byte	0x67
	mulq	%r14
	addq	%rax,%r11
	movq	%rbx,%rax
	movq	8(%rsi,%rcx,1),%rbx
	movq	%rdx,%r10
	adcq	$0,%r10
	addq	%r13,%r11
	adcq	$0,%r10

	mulq	%r15
	addq	%rax,%r12
	movq	%r11,(%rdi,%rcx,1)
	movq	%rbx,%rax
	movq	%rdx,%r13
	adcq	$0,%r13
	addq	8(%rdi,%rcx,1),%r12
	leaq	16(%rcx),%rcx
	adcq	$0,%r13

	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	adcq	$0,%rdx
	addq	%r12,%r10
	movq	%rdx,%r11
	adcq	$0,%r11
	movq	%r10,-8(%rdi,%rcx,1)

	cmpq	$0,%rcx
	jne	L$sqr4x_inner

.byte	0x67
	mulq	%r15
	addq	%rax,%r13
	adcq	$0,%rdx
	addq	%r11,%r13
	adcq	$0,%rdx

	movq	%r13,(%rdi)
	movq	%rdx,%r12
	movq	%rdx,8(%rdi)

	addq	$16,%rbp
	jnz	L$sqr4x_outer


	movq	-32(%rsi),%r14
	leaq	48+8(%rsp,%r9,2),%rdi
	movq	-24(%rsi),%rax
	leaq	-32(%rdi,%rbp,1),%rdi
	movq	-16(%rsi),%rbx
	movq	%rax,%r15

	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	movq	%rdx,%r11
	adcq	$0,%r11

	mulq	%r14
	addq	%rax,%r11
	movq	%rbx,%rax
	movq	%r10,-24(%rdi)
	movq	%rdx,%r10
	adcq	$0,%r10
	addq	%r13,%r11
	movq	-8(%rsi),%rbx
	adcq	$0,%r10

	mulq	%r15
	addq	%rax,%r12
	movq	%rbx,%rax
	movq	%r11,-16(%rdi)
	movq	%rdx,%r13
	adcq	$0,%r13

	mulq	%r14
	addq	%rax,%r10
	movq	%rbx,%rax
	movq	%rdx,%r11
	adcq	$0,%r11
	addq	%r12,%r10
	adcq	$0,%r11
	movq	%r10,-8(%rdi)

	mulq	%r15
	addq	%rax,%r13
	movq	-16(%rsi),%rax
	adcq	$0,%rdx
	addq	%r11,%r13
	adcq	$0,%rdx

	movq	%r13,(%rdi)
	movq	%rdx,%r12
	movq	%rdx,8(%rdi)

	mulq	%rbx
	addq	$16,%rbp
	xorq	%r14,%r14
	subq	%r9,%rbp
	xorq	%r15,%r15

	addq	%r12,%rax
	adcq	$0,%rdx
	movq	%rax,8(%rdi)
	movq	%rdx,16(%rdi)
	movq	%r15,24(%rdi)

	movq	-16(%rsi,%rbp,1),%rax
	leaq	48+8(%rsp),%rdi
	xorq	%r10,%r10
	movq	8(%rdi),%r11

	leaq	(%r14,%r10,2),%r12
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	orq	%r10,%r13
	movq	16(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	24(%rdi),%r11
	adcq	%rax,%r12
	movq	-8(%rsi,%rbp,1),%rax
	movq	%r12,(%rdi)
	adcq	%rdx,%r13

	leaq	(%r14,%r10,2),%rbx
	movq	%r13,8(%rdi)
	sbbq	%r15,%r15
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	orq	%r10,%r8
	movq	32(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	40(%rdi),%r11
	adcq	%rax,%rbx
	movq	0(%rsi,%rbp,1),%rax
	movq	%rbx,16(%rdi)
	adcq	%rdx,%r8
	leaq	16(%rbp),%rbp
	movq	%r8,24(%rdi)
	sbbq	%r15,%r15
	leaq	64(%rdi),%rdi
	jmp	L$sqr4x_shift_n_add

.p2align	5
L$sqr4x_shift_n_add:
	leaq	(%r14,%r10,2),%r12
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	orq	%r10,%r13
	movq	-16(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	-8(%rdi),%r11
	adcq	%rax,%r12
	movq	-8(%rsi,%rbp,1),%rax
	movq	%r12,-32(%rdi)
	adcq	%rdx,%r13

	leaq	(%r14,%r10,2),%rbx
	movq	%r13,-24(%rdi)
	sbbq	%r15,%r15
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	orq	%r10,%r8
	movq	0(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	8(%rdi),%r11
	adcq	%rax,%rbx
	movq	0(%rsi,%rbp,1),%rax
	movq	%rbx,-16(%rdi)
	adcq	%rdx,%r8

	leaq	(%r14,%r10,2),%r12
	movq	%r8,-8(%rdi)
	sbbq	%r15,%r15
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	orq	%r10,%r13
	movq	16(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	24(%rdi),%r11
	adcq	%rax,%r12
	movq	8(%rsi,%rbp,1),%rax
	movq	%r12,0(%rdi)
	adcq	%rdx,%r13

	leaq	(%r14,%r10,2),%rbx
	movq	%r13,8(%rdi)
	sbbq	%r15,%r15
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	orq	%r10,%r8
	movq	32(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	40(%rdi),%r11
	adcq	%rax,%rbx
	movq	16(%rsi,%rbp,1),%rax
	movq	%rbx,16(%rdi)
	adcq	%rdx,%r8
	movq	%r8,24(%rdi)
	sbbq	%r15,%r15
	leaq	64(%rdi),%rdi
	addq	$32,%rbp
	jnz	L$sqr4x_shift_n_add

	leaq	(%r14,%r10,2),%r12
.byte	0x67
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	orq	%r10,%r13
	movq	-16(%rdi),%r10
	movq	%r11,%r14
	mulq	%rax
	negq	%r15
	movq	-8(%rdi),%r11
	adcq	%rax,%r12
	movq	-8(%rsi),%rax
	movq	%r12,-32(%rdi)
	adcq	%rdx,%r13

	leaq	(%r14,%r10,2),%rbx
	movq	%r13,-24(%rdi)
	sbbq	%r15,%r15
	shrq	$63,%r10
	leaq	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	orq	%r10,%r8
	mulq	%rax
	negq	%r15
	adcq	%rax,%rbx
	adcq	%rdx,%r8
	movq	%rbx,-16(%rdi)
	movq	%r8,-8(%rdi)
.byte	102,72,15,126,213
sqr8x_reduction:
	xorq	%rax,%rax
	leaq	(%rbp,%r9,2),%rcx
	leaq	48+8(%rsp,%r9,2),%rdx
	movq	%rcx,0+8(%rsp)
	leaq	48+8(%rsp,%r9,1),%rdi
	movq	%rdx,8+8(%rsp)
	negq	%r9
	jmp	L$8x_reduction_loop

.p2align	5
L$8x_reduction_loop:
	leaq	(%rdi,%r9,1),%rdi
.byte	0x66
	movq	0(%rdi),%rbx
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	%rax,(%rdx)
	leaq	64(%rdi),%rdi

.byte	0x67
	movq	%rbx,%r8
	imulq	32+8(%rsp),%rbx
	movq	0(%rbp),%rax
	movl	$8,%ecx
	jmp	L$8x_reduce

.p2align	5
L$8x_reduce:
	mulq	%rbx
	movq	16(%rbp),%rax
	negq	%r8
	movq	%rdx,%r8
	adcq	$0,%r8

	mulq	%rbx
	addq	%rax,%r9
	movq	32(%rbp),%rax
	adcq	$0,%rdx
	addq	%r9,%r8
	movq	%rbx,48-8+8(%rsp,%rcx,8)
	movq	%rdx,%r9
	adcq	$0,%r9

	mulq	%rbx
	addq	%rax,%r10
	movq	48(%rbp),%rax
	adcq	$0,%rdx
	addq	%r10,%r9
	movq	32+8(%rsp),%rsi
	movq	%rdx,%r10
	adcq	$0,%r10

	mulq	%rbx
	addq	%rax,%r11
	movq	64(%rbp),%rax
	adcq	$0,%rdx
	imulq	%r8,%rsi
	addq	%r11,%r10
	movq	%rdx,%r11
	adcq	$0,%r11

	mulq	%rbx
	addq	%rax,%r12
	movq	80(%rbp),%rax
	adcq	$0,%rdx
	addq	%r12,%r11
	movq	%rdx,%r12
	adcq	$0,%r12

	mulq	%rbx
	addq	%rax,%r13
	movq	96(%rbp),%rax
	adcq	$0,%rdx
	addq	%r13,%r12
	movq	%rdx,%r13
	adcq	$0,%r13

	mulq	%rbx
	addq	%rax,%r14
	movq	112(%rbp),%rax
	adcq	$0,%rdx
	addq	%r14,%r13
	movq	%rdx,%r14
	adcq	$0,%r14

	mulq	%rbx
	movq	%rsi,%rbx
	addq	%rax,%r15
	movq	0(%rbp),%rax
	adcq	$0,%rdx
	addq	%r15,%r14
	movq	%rdx,%r15
	adcq	$0,%r15

	decl	%ecx
	jnz	L$8x_reduce

	leaq	128(%rbp),%rbp
	xorq	%rax,%rax
	movq	8+8(%rsp),%rdx
	cmpq	0+8(%rsp),%rbp
	jae	L$8x_no_tail

.byte	0x66
	addq	0(%rdi),%r8
	adcq	8(%rdi),%r9
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	sbbq	%rsi,%rsi

	movq	48+56+8(%rsp),%rbx
	movl	$8,%ecx
	movq	0(%rbp),%rax
	jmp	L$8x_tail

.p2align	5
L$8x_tail:
	mulq	%rbx
	addq	%rax,%r8
	movq	16(%rbp),%rax
	movq	%r8,(%rdi)
	movq	%rdx,%r8
	adcq	$0,%r8

	mulq	%rbx
	addq	%rax,%r9
	movq	32(%rbp),%rax
	adcq	$0,%rdx
	addq	%r9,%r8
	leaq	8(%rdi),%rdi
	movq	%rdx,%r9
	adcq	$0,%r9

	mulq	%rbx
	addq	%rax,%r10
	movq	48(%rbp),%rax
	adcq	$0,%rdx
	addq	%r10,%r9
	movq	%rdx,%r10
	adcq	$0,%r10

	mulq	%rbx
	addq	%rax,%r11
	movq	64(%rbp),%rax
	adcq	$0,%rdx
	addq	%r11,%r10
	movq	%rdx,%r11
	adcq	$0,%r11

	mulq	%rbx
	addq	%rax,%r12
	movq	80(%rbp),%rax
	adcq	$0,%rdx
	addq	%r12,%r11
	movq	%rdx,%r12
	adcq	$0,%r12

	mulq	%rbx
	addq	%rax,%r13
	movq	96(%rbp),%rax
	adcq	$0,%rdx
	addq	%r13,%r12
	movq	%rdx,%r13
	adcq	$0,%r13

	mulq	%rbx
	addq	%rax,%r14
	movq	112(%rbp),%rax
	adcq	$0,%rdx
	addq	%r14,%r13
	movq	%rdx,%r14
	adcq	$0,%r14

	mulq	%rbx
	movq	48-16+8(%rsp,%rcx,8),%rbx
	addq	%rax,%r15
	adcq	$0,%rdx
	addq	%r15,%r14
	movq	0(%rbp),%rax
	movq	%rdx,%r15
	adcq	$0,%r15

	decl	%ecx
	jnz	L$8x_tail

	leaq	128(%rbp),%rbp
	movq	8+8(%rsp),%rdx
	cmpq	0+8(%rsp),%rbp
	jae	L$8x_tail_done

	movq	48+56+8(%rsp),%rbx
	negq	%rsi
	movq	0(%rbp),%rax
	adcq	0(%rdi),%r8
	adcq	8(%rdi),%r9
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	sbbq	%rsi,%rsi

	movl	$8,%ecx
	jmp	L$8x_tail

.p2align	5
L$8x_tail_done:
	addq	(%rdx),%r8
	xorq	%rax,%rax

	negq	%rsi
L$8x_no_tail:
	adcq	0(%rdi),%r8
	adcq	8(%rdi),%r9
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	adcq	$0,%rax
	movq	-16(%rbp),%rcx
	xorq	%rsi,%rsi

.byte	102,72,15,126,213

	movq	%r8,0(%rdi)
	movq	%r9,8(%rdi)
.byte	102,73,15,126,217
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)
	movq	%r12,32(%rdi)
	movq	%r13,40(%rdi)
	movq	%r14,48(%rdi)
	movq	%r15,56(%rdi)
	leaq	64(%rdi),%rdi

	cmpq	%rdx,%rdi
	jb	L$8x_reduction_loop

	subq	%r15,%rcx
	leaq	(%rdi,%r9,1),%rbx
	adcq	%rsi,%rsi
	movq	%r9,%rcx
	orq	%rsi,%rax
.byte	102,72,15,126,207
	xorq	$1,%rax
.byte	102,72,15,126,206
	leaq	(%rbp,%rax,8),%rbp
	sarq	$3+2,%rcx
	jmp	L$sqr4x_sub

.p2align	5
L$sqr4x_sub:
.byte	0x66
	movq	0(%rbx),%r12
	movq	8(%rbx),%r13
	sbbq	0(%rbp),%r12
	movq	16(%rbx),%r14
	sbbq	16(%rbp),%r13
	movq	24(%rbx),%r15
	leaq	32(%rbx),%rbx
	sbbq	32(%rbp),%r14
	movq	%r12,0(%rdi)
	sbbq	48(%rbp),%r15
	leaq	64(%rbp),%rbp
	movq	%r13,8(%rdi)
	movq	%r14,16(%rdi)
	movq	%r15,24(%rdi)
	leaq	32(%rdi),%rdi

	incq	%rcx
	jnz	L$sqr4x_sub
	movq	%r9,%r10
	negq	%r9
	.byte	0xf3,0xc3

.globl	_bn_from_montgomery

.p2align	5
_bn_from_montgomery:
	testl	$7,%r9d
	jz	bn_from_mont8x
	xorl	%eax,%eax
	.byte	0xf3,0xc3



.p2align	5
bn_from_mont8x:
.byte	0x67
	movq	%rsp,%rax
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
.byte	0x67
	movl	%r9d,%r10d
	shll	$3,%r9d
	shll	$3+2,%r10d
	negq	%r9
	movq	(%r8),%r8







	leaq	-64(%rsp,%r9,2),%r11
	subq	%rsi,%r11
	andq	$4095,%r11
	cmpq	%r11,%r10
	jb	L$from_sp_alt
	subq	%r11,%rsp
	leaq	-64(%rsp,%r9,2),%rsp
	jmp	L$from_sp_done

.p2align	5
L$from_sp_alt:
	leaq	4096-64(,%r9,2),%r10
	leaq	-64(%rsp,%r9,2),%rsp
	subq	%r10,%r11
	movq	$0,%r10
	cmovcq	%r10,%r11
	subq	%r11,%rsp
L$from_sp_done:
	andq	$-64,%rsp
	movq	%r9,%r10
	negq	%r9










	movq	%r8,32(%rsp)
	movq	%rax,40(%rsp)
L$from_body:
	movq	%r9,%r11
	leaq	48(%rsp),%rax
	pxor	%xmm0,%xmm0
	jmp	L$mul_by_1

.p2align	5
L$mul_by_1:
	movdqu	(%rsi),%xmm1
	movdqu	16(%rsi),%xmm2
	movdqu	32(%rsi),%xmm3
	movdqa	%xmm0,(%rax,%r9,1)
	movdqu	48(%rsi),%xmm4
	movdqa	%xmm0,16(%rax,%r9,1)
.byte	0x48,0x8d,0xb6,0x40,0x00,0x00,0x00
	movdqa	%xmm1,(%rax)
	movdqa	%xmm0,32(%rax,%r9,1)
	movdqa	%xmm2,16(%rax)
	movdqa	%xmm0,48(%rax,%r9,1)
	movdqa	%xmm3,32(%rax)
	movdqa	%xmm4,48(%rax)
	leaq	64(%rax),%rax
	subq	$64,%r11
	jnz	L$mul_by_1

.byte	102,72,15,110,207
.byte	102,72,15,110,209
.byte	0x67
	movq	%rcx,%rbp
.byte	102,73,15,110,218
	movl	_OPENSSL_ia32cap_P+8(%rip),%r11d
	andl	$524544,%r11d
	cmpl	$524544,%r11d
	jne	L$from_mont_nox

	leaq	(%rax,%r9,1),%rdi
	call	sqrx8x_reduction

	pxor	%xmm0,%xmm0
	leaq	48(%rsp),%rax
	movq	40(%rsp),%rsi
	jmp	L$from_mont_zero

.p2align	5
L$from_mont_nox:
	call	sqr8x_reduction

	pxor	%xmm0,%xmm0
	leaq	48(%rsp),%rax
	movq	40(%rsp),%rsi
	jmp	L$from_mont_zero

.p2align	5
L$from_mont_zero:
	movdqa	%xmm0,0(%rax)
	movdqa	%xmm0,16(%rax)
	movdqa	%xmm0,32(%rax)
	movdqa	%xmm0,48(%rax)
	leaq	64(%rax),%rax
	subq	$32,%r9
	jnz	L$from_mont_zero

	movq	$1,%rax
	movq	-48(%rsi),%r15
	movq	-40(%rsi),%r14
	movq	-32(%rsi),%r13
	movq	-24(%rsi),%r12
	movq	-16(%rsi),%rbp
	movq	-8(%rsi),%rbx
	leaq	(%rsi),%rsp
L$from_epilogue:
	.byte	0xf3,0xc3


.p2align	5
bn_mulx4x_mont_gather5:
L$mulx4x_enter:
.byte	0x67
	movq	%rsp,%rax
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
.byte	0x67
	movl	%r9d,%r10d
	shll	$3,%r9d
	shll	$3+2,%r10d
	negq	%r9
	movq	(%r8),%r8








	leaq	-64(%rsp,%r9,2),%r11
	subq	%rsi,%r11
	andq	$4095,%r11
	cmpq	%r11,%r10
	jb	L$mulx4xsp_alt
	subq	%r11,%rsp
	leaq	-64(%rsp,%r9,2),%rsp
	jmp	L$mulx4xsp_done

.p2align	5
L$mulx4xsp_alt:
	leaq	4096-64(,%r9,2),%r10
	leaq	-64(%rsp,%r9,2),%rsp
	subq	%r10,%r11
	movq	$0,%r10
	cmovcq	%r10,%r11
	subq	%r11,%rsp
L$mulx4xsp_done:
	andq	$-64,%rsp












	movq	%r8,32(%rsp)
	movq	%rax,40(%rsp)
L$mulx4x_body:
	call	mulx4x_internal

	movq	40(%rsp),%rsi
	movq	$1,%rax
	movq	-48(%rsi),%r15
	movq	-40(%rsi),%r14
	movq	-32(%rsi),%r13
	movq	-24(%rsi),%r12
	movq	-16(%rsi),%rbp
	movq	-8(%rsi),%rbx
	leaq	(%rsi),%rsp
L$mulx4x_epilogue:
	.byte	0xf3,0xc3



.p2align	5
mulx4x_internal:
.byte	0x4c,0x89,0x8c,0x24,0x08,0x00,0x00,0x00
.byte	0x67
	negq	%r9
	shlq	$5,%r9
	leaq	256(%rdx,%r9,1),%r13
	shrq	$5+5,%r9
	movl	8(%rax),%r10d
	subq	$1,%r9
	movq	%r13,16+8(%rsp)
	movq	%r9,24+8(%rsp)
	movq	%rdi,56+8(%rsp)
	movq	%r10,%r11
	shrq	$3,%r10
	andq	$7,%r11
	notq	%r10
	leaq	L$magic_masks(%rip),%rax
	andq	$3,%r10
	leaq	96(%rdx,%r11,8),%rdi
	movq	0(%rax,%r10,8),%xmm4
	movq	8(%rax,%r10,8),%xmm5
	addq	$7,%r11
	movq	16(%rax,%r10,8),%xmm6
	movq	24(%rax,%r10,8),%xmm7
	andq	$7,%r11

	movq	-96(%rdi),%xmm0
	leaq	256(%rdi),%rbx
	movq	-32(%rdi),%xmm1
	pand	%xmm4,%xmm0
	movq	32(%rdi),%xmm2
	pand	%xmm5,%xmm1
	movq	96(%rdi),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	movq	-96(%rbx),%xmm1
	pand	%xmm7,%xmm3
	por	%xmm2,%xmm0
	movq	-32(%rbx),%xmm2
	por	%xmm3,%xmm0
.byte	0x67,0x67
	pand	%xmm4,%xmm1
	movq	32(%rbx),%xmm3

.byte	102,72,15,126,194
	movq	96(%rbx),%xmm0
	leaq	512(%rdi),%rdi
	pand	%xmm5,%xmm2
.byte	0x67,0x67
	pand	%xmm6,%xmm3







	leaq	64+32+8(%rsp,%r11,8),%rbx

	movq	%rdx,%r9
	mulxq	0(%rsi),%r8,%rax
	mulxq	8(%rsi),%r11,%r12
	addq	%rax,%r11
	mulxq	16(%rsi),%rax,%r13
	adcq	%rax,%r12
	adcq	$0,%r13
	mulxq	24(%rsi),%rax,%r14

	movq	%r8,%r15
	imulq	32+8(%rsp),%r8
	xorq	%rbp,%rbp
	movq	%r8,%rdx

	por	%xmm2,%xmm1
	pand	%xmm7,%xmm0
	por	%xmm3,%xmm1
	movq	%rdi,8+8(%rsp)
	por	%xmm1,%xmm0

.byte	0x48,0x8d,0xb6,0x20,0x00,0x00,0x00
	adcxq	%rax,%r13
	adcxq	%rbp,%r14

	mulxq	0(%rcx),%rax,%r10
	adcxq	%rax,%r15
	adoxq	%r11,%r10
	mulxq	16(%rcx),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11
	mulxq	32(%rcx),%rax,%r12
	movq	24+8(%rsp),%rdi
.byte	0x66
	movq	%r10,-32(%rbx)
	adcxq	%rax,%r11
	adoxq	%r13,%r12
	mulxq	48(%rcx),%rax,%r15
.byte	0x67,0x67
	movq	%r9,%rdx
	movq	%r11,-24(%rbx)
	adcxq	%rax,%r12
	adoxq	%rbp,%r15
.byte	0x48,0x8d,0x89,0x40,0x00,0x00,0x00
	movq	%r12,-16(%rbx)


.p2align	5
L$mulx4x_1st:
	adcxq	%rbp,%r15
	mulxq	0(%rsi),%r10,%rax
	adcxq	%r14,%r10
	mulxq	8(%rsi),%r11,%r14
	adcxq	%rax,%r11
	mulxq	16(%rsi),%r12,%rax
	adcxq	%r14,%r12
	mulxq	24(%rsi),%r13,%r14
.byte	0x67,0x67
	movq	%r8,%rdx
	adcxq	%rax,%r13
	adcxq	%rbp,%r14
	leaq	32(%rsi),%rsi
	leaq	32(%rbx),%rbx

	adoxq	%r15,%r10
	mulxq	0(%rcx),%rax,%r15
	adcxq	%rax,%r10
	adoxq	%r15,%r11
	mulxq	16(%rcx),%rax,%r15
	adcxq	%rax,%r11
	adoxq	%r15,%r12
	mulxq	32(%rcx),%rax,%r15
	movq	%r10,-40(%rbx)
	adcxq	%rax,%r12
	movq	%r11,-32(%rbx)
	adoxq	%r15,%r13
	mulxq	48(%rcx),%rax,%r15
	movq	%r9,%rdx
	movq	%r12,-24(%rbx)
	adcxq	%rax,%r13
	adoxq	%rbp,%r15
	leaq	64(%rcx),%rcx
	movq	%r13,-16(%rbx)

	decq	%rdi
	jnz	L$mulx4x_1st

	movq	8(%rsp),%rax
.byte	102,72,15,126,194
	adcq	%rbp,%r15
	leaq	(%rsi,%rax,1),%rsi
	addq	%r15,%r14
	movq	8+8(%rsp),%rdi
	adcq	%rbp,%rbp
	movq	%r14,-8(%rbx)
	jmp	L$mulx4x_outer

.p2align	5
L$mulx4x_outer:
	movq	%rbp,(%rbx)
	leaq	32(%rbx,%rax,1),%rbx
	mulxq	0(%rsi),%r8,%r11
	xorq	%rbp,%rbp
	movq	%rdx,%r9
	mulxq	8(%rsi),%r14,%r12
	adoxq	-32(%rbx),%r8
	adcxq	%r14,%r11
	mulxq	16(%rsi),%r15,%r13
	adoxq	-24(%rbx),%r11
	adcxq	%r15,%r12
	mulxq	24(%rsi),%rdx,%r14
	adoxq	-16(%rbx),%r12
	adcxq	%rdx,%r13
	leaq	(%rcx,%rax,2),%rcx
	leaq	32(%rsi),%rsi
	adoxq	-8(%rbx),%r13
	adcxq	%rbp,%r14
	adoxq	%rbp,%r14

.byte	0x67
	movq	%r8,%r15
	imulq	32+8(%rsp),%r8

	movq	-96(%rdi),%xmm0
.byte	0x67,0x67
	movq	%r8,%rdx
	movq	-32(%rdi),%xmm1
.byte	0x67
	pand	%xmm4,%xmm0
	movq	32(%rdi),%xmm2
.byte	0x67
	pand	%xmm5,%xmm1
	movq	96(%rdi),%xmm3
	addq	$256,%rdi
.byte	0x67
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3
	xorq	%rbp,%rbp
	movq	%rdi,8+8(%rsp)

	mulxq	0(%rcx),%rax,%r10
	adcxq	%rax,%r15
	adoxq	%r11,%r10
	mulxq	16(%rcx),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11
	mulxq	32(%rcx),%rax,%r12
	adcxq	%rax,%r11
	adoxq	%r13,%r12
	mulxq	48(%rcx),%rax,%r15
	movq	%r9,%rdx
	por	%xmm2,%xmm0
	movq	24+8(%rsp),%rdi
	movq	%r10,-32(%rbx)
	por	%xmm3,%xmm0
	adcxq	%rax,%r12
	movq	%r11,-24(%rbx)
	adoxq	%rbp,%r15
	movq	%r12,-16(%rbx)
	leaq	64(%rcx),%rcx
	jmp	L$mulx4x_inner

.p2align	5
L$mulx4x_inner:
	mulxq	0(%rsi),%r10,%rax
	adcxq	%rbp,%r15
	adoxq	%r14,%r10
	mulxq	8(%rsi),%r11,%r14
	adcxq	0(%rbx),%r10
	adoxq	%rax,%r11
	mulxq	16(%rsi),%r12,%rax
	adcxq	8(%rbx),%r11
	adoxq	%r14,%r12
	mulxq	24(%rsi),%r13,%r14
	movq	%r8,%rdx
	adcxq	16(%rbx),%r12
	adoxq	%rax,%r13
	adcxq	24(%rbx),%r13
	adoxq	%rbp,%r14
	leaq	32(%rsi),%rsi
	leaq	32(%rbx),%rbx
	adcxq	%rbp,%r14

	adoxq	%r15,%r10
	mulxq	0(%rcx),%rax,%r15
	adcxq	%rax,%r10
	adoxq	%r15,%r11
	mulxq	16(%rcx),%rax,%r15
	adcxq	%rax,%r11
	adoxq	%r15,%r12
	mulxq	32(%rcx),%rax,%r15
	movq	%r10,-40(%rbx)
	adcxq	%rax,%r12
	adoxq	%r15,%r13
	movq	%r11,-32(%rbx)
	mulxq	48(%rcx),%rax,%r15
	movq	%r9,%rdx
	leaq	64(%rcx),%rcx
	movq	%r12,-24(%rbx)
	adcxq	%rax,%r13
	adoxq	%rbp,%r15
	movq	%r13,-16(%rbx)

	decq	%rdi
	jnz	L$mulx4x_inner

	movq	0+8(%rsp),%rax
.byte	102,72,15,126,194
	adcq	%rbp,%r15
	subq	0(%rbx),%rdi
	movq	8+8(%rsp),%rdi
	movq	16+8(%rsp),%r10
	adcq	%r15,%r14
	leaq	(%rsi,%rax,1),%rsi
	adcq	%rbp,%rbp
	movq	%r14,-8(%rbx)

	cmpq	%r10,%rdi
	jb	L$mulx4x_outer

	movq	-16(%rcx),%r10
	xorq	%r15,%r15
	subq	%r14,%r10
	adcq	%r15,%r15
	orq	%r15,%rbp
	xorq	$1,%rbp
	leaq	(%rbx,%rax,1),%rdi
	leaq	(%rcx,%rax,2),%rcx
.byte	0x67,0x67
	sarq	$3+2,%rax
	leaq	(%rcx,%rbp,8),%rbp
	movq	56+8(%rsp),%rdx
	movq	%rax,%rcx
	jmp	L$sqrx4x_sub


.p2align	5
bn_powerx5:
L$powerx5_enter:
.byte	0x67
	movq	%rsp,%rax
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
.byte	0x67
	movl	%r9d,%r10d
	shll	$3,%r9d
	shll	$3+2,%r10d
	negq	%r9
	movq	(%r8),%r8







	leaq	-64(%rsp,%r9,2),%r11
	subq	%rsi,%r11
	andq	$4095,%r11
	cmpq	%r11,%r10
	jb	L$pwrx_sp_alt
	subq	%r11,%rsp
	leaq	-64(%rsp,%r9,2),%rsp
	jmp	L$pwrx_sp_done

.p2align	5
L$pwrx_sp_alt:
	leaq	4096-64(,%r9,2),%r10
	leaq	-64(%rsp,%r9,2),%rsp
	subq	%r10,%r11
	movq	$0,%r10
	cmovcq	%r10,%r11
	subq	%r11,%rsp
L$pwrx_sp_done:
	andq	$-64,%rsp
	movq	%r9,%r10
	negq	%r9












	pxor	%xmm0,%xmm0
.byte	102,72,15,110,207
.byte	102,72,15,110,209
.byte	102,73,15,110,218
.byte	102,72,15,110,226
	movq	%r8,32(%rsp)
	movq	%rax,40(%rsp)
L$powerx5_body:

	call	__bn_sqrx8x_internal
	call	__bn_sqrx8x_internal
	call	__bn_sqrx8x_internal
	call	__bn_sqrx8x_internal
	call	__bn_sqrx8x_internal

	movq	%r10,%r9
	movq	%rsi,%rdi
.byte	102,72,15,126,209
.byte	102,72,15,126,226
	movq	40(%rsp),%rax

	call	mulx4x_internal

	movq	40(%rsp),%rsi
	movq	$1,%rax
	movq	-48(%rsi),%r15
	movq	-40(%rsi),%r14
	movq	-32(%rsi),%r13
	movq	-24(%rsi),%r12
	movq	-16(%rsi),%rbp
	movq	-8(%rsi),%rbx
	leaq	(%rsi),%rsp
L$powerx5_epilogue:
	.byte	0xf3,0xc3


.globl	_bn_sqrx8x_internal
.private_extern	_bn_sqrx8x_internal

.p2align	5
_bn_sqrx8x_internal:
__bn_sqrx8x_internal:








































	leaq	48+8(%rsp),%rdi
	leaq	(%rsi,%r9,1),%rbp
	movq	%r9,0+8(%rsp)
	movq	%rbp,8+8(%rsp)
	jmp	L$sqr8x_zero_start

.p2align	5
.byte	0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00
L$sqrx8x_zero:
.byte	0x3e
	movdqa	%xmm0,0(%rdi)
	movdqa	%xmm0,16(%rdi)
	movdqa	%xmm0,32(%rdi)
	movdqa	%xmm0,48(%rdi)
L$sqr8x_zero_start:
	movdqa	%xmm0,64(%rdi)
	movdqa	%xmm0,80(%rdi)
	movdqa	%xmm0,96(%rdi)
	movdqa	%xmm0,112(%rdi)
	leaq	128(%rdi),%rdi
	subq	$64,%r9
	jnz	L$sqrx8x_zero

	movq	0(%rsi),%rdx

	xorq	%r10,%r10
	xorq	%r11,%r11
	xorq	%r12,%r12
	xorq	%r13,%r13
	xorq	%r14,%r14
	xorq	%r15,%r15
	leaq	48+8(%rsp),%rdi
	xorq	%rbp,%rbp
	jmp	L$sqrx8x_outer_loop

.p2align	5
L$sqrx8x_outer_loop:
	mulxq	8(%rsi),%r8,%rax
	adcxq	%r9,%r8
	adoxq	%rax,%r10
	mulxq	16(%rsi),%r9,%rax
	adcxq	%r10,%r9
	adoxq	%rax,%r11
.byte	0xc4,0xe2,0xab,0xf6,0x86,0x18,0x00,0x00,0x00
	adcxq	%r11,%r10
	adoxq	%rax,%r12
.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x20,0x00,0x00,0x00
	adcxq	%r12,%r11
	adoxq	%rax,%r13
	mulxq	40(%rsi),%r12,%rax
	adcxq	%r13,%r12
	adoxq	%rax,%r14
	mulxq	48(%rsi),%r13,%rax
	adcxq	%r14,%r13
	adoxq	%r15,%rax
	mulxq	56(%rsi),%r14,%r15
	movq	8(%rsi),%rdx
	adcxq	%rax,%r14
	adoxq	%rbp,%r15
	adcq	64(%rdi),%r15
	movq	%r8,8(%rdi)
	movq	%r9,16(%rdi)
	sbbq	%rcx,%rcx
	xorq	%rbp,%rbp


	mulxq	16(%rsi),%r8,%rbx
	mulxq	24(%rsi),%r9,%rax
	adcxq	%r10,%r8
	adoxq	%rbx,%r9
	mulxq	32(%rsi),%r10,%rbx
	adcxq	%r11,%r9
	adoxq	%rax,%r10
.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x28,0x00,0x00,0x00
	adcxq	%r12,%r10
	adoxq	%rbx,%r11
.byte	0xc4,0xe2,0x9b,0xf6,0x9e,0x30,0x00,0x00,0x00
	adcxq	%r13,%r11
	adoxq	%r14,%r12
.byte	0xc4,0x62,0x93,0xf6,0xb6,0x38,0x00,0x00,0x00
	movq	16(%rsi),%rdx
	adcxq	%rax,%r12
	adoxq	%rbx,%r13
	adcxq	%r15,%r13
	adoxq	%rbp,%r14
	adcxq	%rbp,%r14

	movq	%r8,24(%rdi)
	movq	%r9,32(%rdi)

	mulxq	24(%rsi),%r8,%rbx
	mulxq	32(%rsi),%r9,%rax
	adcxq	%r10,%r8
	adoxq	%rbx,%r9
	mulxq	40(%rsi),%r10,%rbx
	adcxq	%r11,%r9
	adoxq	%rax,%r10
.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x30,0x00,0x00,0x00
	adcxq	%r12,%r10
	adoxq	%r13,%r11
.byte	0xc4,0x62,0x9b,0xf6,0xae,0x38,0x00,0x00,0x00
.byte	0x3e
	movq	24(%rsi),%rdx
	adcxq	%rbx,%r11
	adoxq	%rax,%r12
	adcxq	%r14,%r12
	movq	%r8,40(%rdi)
	movq	%r9,48(%rdi)
	mulxq	32(%rsi),%r8,%rax
	adoxq	%rbp,%r13
	adcxq	%rbp,%r13

	mulxq	40(%rsi),%r9,%rbx
	adcxq	%r10,%r8
	adoxq	%rax,%r9
	mulxq	48(%rsi),%r10,%rax
	adcxq	%r11,%r9
	adoxq	%r12,%r10
	mulxq	56(%rsi),%r11,%r12
	movq	32(%rsi),%rdx
	movq	40(%rsi),%r14
	adcxq	%rbx,%r10
	adoxq	%rax,%r11
	movq	48(%rsi),%r15
	adcxq	%r13,%r11
	adoxq	%rbp,%r12
	adcxq	%rbp,%r12

	movq	%r8,56(%rdi)
	movq	%r9,64(%rdi)

	mulxq	%r14,%r9,%rax
	movq	56(%rsi),%r8
	adcxq	%r10,%r9
	mulxq	%r15,%r10,%rbx
	adoxq	%rax,%r10
	adcxq	%r11,%r10
	mulxq	%r8,%r11,%rax
	movq	%r14,%rdx
	adoxq	%rbx,%r11
	adcxq	%r12,%r11

	adcxq	%rbp,%rax

	mulxq	%r15,%r14,%rbx
	mulxq	%r8,%r12,%r13
	movq	%r15,%rdx
	leaq	64(%rsi),%rsi
	adcxq	%r14,%r11
	adoxq	%rbx,%r12
	adcxq	%rax,%r12
	adoxq	%rbp,%r13

.byte	0x67,0x67
	mulxq	%r8,%r8,%r14
	adcxq	%r8,%r13
	adcxq	%rbp,%r14

	cmpq	8+8(%rsp),%rsi
	je	L$sqrx8x_outer_break

	negq	%rcx
	movq	$-8,%rcx
	movq	%rbp,%r15
	movq	64(%rdi),%r8
	adcxq	72(%rdi),%r9
	adcxq	80(%rdi),%r10
	adcxq	88(%rdi),%r11
	adcq	96(%rdi),%r12
	adcq	104(%rdi),%r13
	adcq	112(%rdi),%r14
	adcq	120(%rdi),%r15
	leaq	(%rsi),%rbp
	leaq	128(%rdi),%rdi
	sbbq	%rax,%rax

	movq	-64(%rsi),%rdx
	movq	%rax,16+8(%rsp)
	movq	%rdi,24+8(%rsp)


	xorl	%eax,%eax
	jmp	L$sqrx8x_loop

.p2align	5
L$sqrx8x_loop:
	movq	%r8,%rbx
	mulxq	0(%rbp),%rax,%r8
	adcxq	%rax,%rbx
	adoxq	%r9,%r8

	mulxq	8(%rbp),%rax,%r9
	adcxq	%rax,%r8
	adoxq	%r10,%r9

	mulxq	16(%rbp),%rax,%r10
	adcxq	%rax,%r9
	adoxq	%r11,%r10

	mulxq	24(%rbp),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11

.byte	0xc4,0x62,0xfb,0xf6,0xa5,0x20,0x00,0x00,0x00
	adcxq	%rax,%r11
	adoxq	%r13,%r12

	mulxq	40(%rbp),%rax,%r13
	adcxq	%rax,%r12
	adoxq	%r14,%r13

	mulxq	48(%rbp),%rax,%r14
	movq	%rbx,(%rdi,%rcx,8)
	movl	$0,%ebx
	adcxq	%rax,%r13
	adoxq	%r15,%r14

.byte	0xc4,0x62,0xfb,0xf6,0xbd,0x38,0x00,0x00,0x00
	movq	8(%rsi,%rcx,8),%rdx
	adcxq	%rax,%r14
	adoxq	%rbx,%r15
	adcxq	%rbx,%r15

.byte	0x67
	incq	%rcx
	jnz	L$sqrx8x_loop

	leaq	64(%rbp),%rbp
	movq	$-8,%rcx
	cmpq	8+8(%rsp),%rbp
	je	L$sqrx8x_break

	subq	16+8(%rsp),%rbx
.byte	0x66
	movq	-64(%rsi),%rdx
	adcxq	0(%rdi),%r8
	adcxq	8(%rdi),%r9
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	leaq	64(%rdi),%rdi
.byte	0x67
	sbbq	%rax,%rax
	xorl	%ebx,%ebx
	movq	%rax,16+8(%rsp)
	jmp	L$sqrx8x_loop

.p2align	5
L$sqrx8x_break:
	subq	16+8(%rsp),%r8
	movq	24+8(%rsp),%rcx
	movq	0(%rsi),%rdx
	xorl	%ebp,%ebp
	movq	%r8,0(%rdi)
	cmpq	%rcx,%rdi
	je	L$sqrx8x_outer_loop

	movq	%r9,8(%rdi)
	movq	8(%rcx),%r9
	movq	%r10,16(%rdi)
	movq	16(%rcx),%r10
	movq	%r11,24(%rdi)
	movq	24(%rcx),%r11
	movq	%r12,32(%rdi)
	movq	32(%rcx),%r12
	movq	%r13,40(%rdi)
	movq	40(%rcx),%r13
	movq	%r14,48(%rdi)
	movq	48(%rcx),%r14
	movq	%r15,56(%rdi)
	movq	56(%rcx),%r15
	movq	%rcx,%rdi
	jmp	L$sqrx8x_outer_loop

.p2align	5
L$sqrx8x_outer_break:
	movq	%r9,72(%rdi)
.byte	102,72,15,126,217
	movq	%r10,80(%rdi)
	movq	%r11,88(%rdi)
	movq	%r12,96(%rdi)
	movq	%r13,104(%rdi)
	movq	%r14,112(%rdi)
	leaq	48+8(%rsp),%rdi
	movq	(%rsi,%rcx,1),%rdx

	movq	8(%rdi),%r11
	xorq	%r10,%r10
	movq	0+8(%rsp),%r9
	adoxq	%r11,%r11
	movq	16(%rdi),%r12
	movq	24(%rdi),%r13


.p2align	5
L$sqrx4x_shift_n_add:
	mulxq	%rdx,%rax,%rbx
	adoxq	%r12,%r12
	adcxq	%r10,%rax
.byte	0x48,0x8b,0x94,0x0e,0x08,0x00,0x00,0x00
.byte	0x4c,0x8b,0x97,0x20,0x00,0x00,0x00
	adoxq	%r13,%r13
	adcxq	%r11,%rbx
	movq	40(%rdi),%r11
	movq	%rax,0(%rdi)
	movq	%rbx,8(%rdi)

	mulxq	%rdx,%rax,%rbx
	adoxq	%r10,%r10
	adcxq	%r12,%rax
	movq	16(%rsi,%rcx,1),%rdx
	movq	48(%rdi),%r12
	adoxq	%r11,%r11
	adcxq	%r13,%rbx
	movq	56(%rdi),%r13
	movq	%rax,16(%rdi)
	movq	%rbx,24(%rdi)

	mulxq	%rdx,%rax,%rbx
	adoxq	%r12,%r12
	adcxq	%r10,%rax
	movq	24(%rsi,%rcx,1),%rdx
	leaq	32(%rcx),%rcx
	movq	64(%rdi),%r10
	adoxq	%r13,%r13
	adcxq	%r11,%rbx
	movq	72(%rdi),%r11
	movq	%rax,32(%rdi)
	movq	%rbx,40(%rdi)

	mulxq	%rdx,%rax,%rbx
	adoxq	%r10,%r10
	adcxq	%r12,%rax
	jrcxz	L$sqrx4x_shift_n_add_break
.byte	0x48,0x8b,0x94,0x0e,0x00,0x00,0x00,0x00
	adoxq	%r11,%r11
	adcxq	%r13,%rbx
	movq	80(%rdi),%r12
	movq	88(%rdi),%r13
	movq	%rax,48(%rdi)
	movq	%rbx,56(%rdi)
	leaq	64(%rdi),%rdi
	nop
	jmp	L$sqrx4x_shift_n_add

.p2align	5
L$sqrx4x_shift_n_add_break:
	adcxq	%r13,%rbx
	movq	%rax,48(%rdi)
	movq	%rbx,56(%rdi)
	leaq	64(%rdi),%rdi
.byte	102,72,15,126,213
sqrx8x_reduction:
	xorl	%eax,%eax
	movq	32+8(%rsp),%rbx
	movq	48+8(%rsp),%rdx
	leaq	-128(%rbp,%r9,2),%rcx

	movq	%rcx,0+8(%rsp)
	movq	%rdi,8+8(%rsp)

	leaq	48+8(%rsp),%rdi
	jmp	L$sqrx8x_reduction_loop

.p2align	5
L$sqrx8x_reduction_loop:
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	%rdx,%r8
	imulq	%rbx,%rdx
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	%rax,24+8(%rsp)

	leaq	64(%rdi),%rdi
	xorq	%rsi,%rsi
	movq	$-8,%rcx
	jmp	L$sqrx8x_reduce

.p2align	5
L$sqrx8x_reduce:
	movq	%r8,%rbx
	mulxq	0(%rbp),%rax,%r8
	adcxq	%rbx,%rax
	adoxq	%r9,%r8

	mulxq	16(%rbp),%rbx,%r9
	adcxq	%rbx,%r8
	adoxq	%r10,%r9

	mulxq	32(%rbp),%rbx,%r10
	adcxq	%rbx,%r9
	adoxq	%r11,%r10

	mulxq	48(%rbp),%rbx,%r11
	adcxq	%rbx,%r10
	adoxq	%r12,%r11

.byte	0xc4,0x62,0xe3,0xf6,0xa5,0x40,0x00,0x00,0x00
	movq	%rdx,%rax
	movq	%r8,%rdx
	adcxq	%rbx,%r11
	adoxq	%r13,%r12

	mulxq	32+8(%rsp),%rbx,%rdx
	movq	%rax,%rdx
	movq	%rax,64+48+8(%rsp,%rcx,8)

	mulxq	80(%rbp),%rax,%r13
	adcxq	%rax,%r12
	adoxq	%r14,%r13

	mulxq	96(%rbp),%rax,%r14
	adcxq	%rax,%r13
	adoxq	%r15,%r14

	mulxq	112(%rbp),%rax,%r15
	movq	%rbx,%rdx
	adcxq	%rax,%r14
	adoxq	%rsi,%r15
	adcxq	%rsi,%r15

.byte	0x67,0x67,0x67
	incq	%rcx
	jnz	L$sqrx8x_reduce

	movq	%rsi,%rax
	cmpq	0+8(%rsp),%rbp
	jae	L$sqrx8x_no_tail

	movq	48+8(%rsp),%rdx
	addq	0(%rdi),%r8
	leaq	128(%rbp),%rbp
	movq	$-8,%rcx
	adcxq	8(%rdi),%r9
	adcxq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	leaq	64(%rdi),%rdi
	sbbq	%rax,%rax

	xorq	%rsi,%rsi
	movq	%rax,16+8(%rsp)
	jmp	L$sqrx8x_tail

.p2align	5
L$sqrx8x_tail:
	movq	%r8,%rbx
	mulxq	0(%rbp),%rax,%r8
	adcxq	%rax,%rbx
	adoxq	%r9,%r8

	mulxq	16(%rbp),%rax,%r9
	adcxq	%rax,%r8
	adoxq	%r10,%r9

	mulxq	32(%rbp),%rax,%r10
	adcxq	%rax,%r9
	adoxq	%r11,%r10

	mulxq	48(%rbp),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11

.byte	0xc4,0x62,0xfb,0xf6,0xa5,0x40,0x00,0x00,0x00
	adcxq	%rax,%r11
	adoxq	%r13,%r12

	mulxq	80(%rbp),%rax,%r13
	adcxq	%rax,%r12
	adoxq	%r14,%r13

	mulxq	96(%rbp),%rax,%r14
	adcxq	%rax,%r13
	adoxq	%r15,%r14

	mulxq	112(%rbp),%rax,%r15
	movq	72+48+8(%rsp,%rcx,8),%rdx
	adcxq	%rax,%r14
	adoxq	%rsi,%r15
	movq	%rbx,(%rdi,%rcx,8)
	movq	%r8,%rbx
	adcxq	%rsi,%r15

	incq	%rcx
	jnz	L$sqrx8x_tail

	cmpq	0+8(%rsp),%rbp
	jae	L$sqrx8x_tail_done

	subq	16+8(%rsp),%rsi
	movq	48+8(%rsp),%rdx
	leaq	128(%rbp),%rbp
	adcq	0(%rdi),%r8
	adcq	8(%rdi),%r9
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	leaq	64(%rdi),%rdi
	sbbq	%rax,%rax
	subq	$8,%rcx

	xorq	%rsi,%rsi
	movq	%rax,16+8(%rsp)
	jmp	L$sqrx8x_tail

.p2align	5
L$sqrx8x_tail_done:
	addq	24+8(%rsp),%r8
	movq	%rsi,%rax

	subq	16+8(%rsp),%rsi
L$sqrx8x_no_tail:
	adcq	0(%rdi),%r8
.byte	102,72,15,126,217
	adcq	8(%rdi),%r9
	movq	112(%rbp),%rsi
.byte	102,72,15,126,213
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	adcq	48(%rdi),%r14
	adcq	56(%rdi),%r15
	adcq	%rax,%rax

	movq	32+8(%rsp),%rbx
	movq	64(%rdi,%rcx,1),%rdx

	movq	%r8,0(%rdi)
	leaq	64(%rdi),%r8
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)
	movq	%r12,32(%rdi)
	movq	%r13,40(%rdi)
	movq	%r14,48(%rdi)
	movq	%r15,56(%rdi)

	leaq	64(%rdi,%rcx,1),%rdi
	cmpq	8+8(%rsp),%r8
	jb	L$sqrx8x_reduction_loop
	xorq	%rbx,%rbx
	subq	%r15,%rsi
	adcq	%rbx,%rbx
	movq	%rcx,%r10
.byte	0x67
	orq	%rbx,%rax
.byte	0x67
	movq	%rcx,%r9
	xorq	$1,%rax
	sarq	$3+2,%rcx

	leaq	(%rbp,%rax,8),%rbp
.byte	102,72,15,126,202
.byte	102,72,15,126,206
	jmp	L$sqrx4x_sub

.p2align	5
L$sqrx4x_sub:
.byte	0x66
	movq	0(%rdi),%r12
	movq	8(%rdi),%r13
	sbbq	0(%rbp),%r12
	movq	16(%rdi),%r14
	sbbq	16(%rbp),%r13
	movq	24(%rdi),%r15
	leaq	32(%rdi),%rdi
	sbbq	32(%rbp),%r14
	movq	%r12,0(%rdx)
	sbbq	48(%rbp),%r15
	leaq	64(%rbp),%rbp
	movq	%r13,8(%rdx)
	movq	%r14,16(%rdx)
	movq	%r15,24(%rdx)
	leaq	32(%rdx),%rdx

	incq	%rcx
	jnz	L$sqrx4x_sub
	negq	%r9

	.byte	0xf3,0xc3

.globl	_bn_get_bits5

.p2align	4
_bn_get_bits5:
	movq	%rdi,%r10
	movl	%esi,%ecx
	shrl	$3,%esi
	movzwl	(%r10,%rsi,1),%eax
	andl	$7,%ecx
	shrl	%cl,%eax
	andl	$31,%eax
	.byte	0xf3,0xc3


.globl	_bn_scatter5

.p2align	4
_bn_scatter5:
	cmpl	$0,%esi
	jz	L$scatter_epilogue
	leaq	(%rdx,%rcx,8),%rdx
L$scatter:
	movq	(%rdi),%rax
	leaq	8(%rdi),%rdi
	movq	%rax,(%rdx)
	leaq	256(%rdx),%rdx
	subl	$1,%esi
	jnz	L$scatter
L$scatter_epilogue:
	.byte	0xf3,0xc3


.globl	_bn_gather5

.p2align	4
_bn_gather5:
	movl	%ecx,%r11d
	shrl	$3,%ecx
	andq	$7,%r11
	notl	%ecx
	leaq	L$magic_masks(%rip),%rax
	andl	$3,%ecx
	leaq	128(%rdx,%r11,8),%rdx
	movq	0(%rax,%rcx,8),%xmm4
	movq	8(%rax,%rcx,8),%xmm5
	movq	16(%rax,%rcx,8),%xmm6
	movq	24(%rax,%rcx,8),%xmm7
	jmp	L$gather
.p2align	4
L$gather:
	movq	-128(%rdx),%xmm0
	movq	-64(%rdx),%xmm1
	pand	%xmm4,%xmm0
	movq	0(%rdx),%xmm2
	pand	%xmm5,%xmm1
	movq	64(%rdx),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3
.byte	0x67,0x67
	por	%xmm2,%xmm0
	leaq	256(%rdx),%rdx
	por	%xmm3,%xmm0

	movq	%xmm0,(%rdi)
	leaq	8(%rdi),%rdi
	subl	$1,%esi
	jnz	L$gather
	.byte	0xf3,0xc3
L$SEH_end_bn_gather5:

.p2align	6
L$magic_masks:
.long	0,0, 0,0, 0,0, -1,-1
.long	0,0, 0,0, 0,0,  0,0
.byte	77,111,110,116,103,111,109,101,114,121,32,77,117,108,116,105,112,108,105,99,97,116,105,111,110,32,119,105,116,104,32,115,99,97,116,116,101,114,47,103,97,116,104,101,114,32,102,111,114,32,120,56,54,95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
