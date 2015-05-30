.text



.globl	_bn_mul_mont_gather5

.p2align	6
_bn_mul_mont_gather5:
	testl	$7,%r9d
	jnz	L$mul_enter
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
