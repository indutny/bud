TITLE	ghash-x86.asm
IF @Version LT 800
ECHO MASM version 8.00 or later is strongly recommended.
ENDIF
.686
.XMM
IF @Version LT 800
XMMWORD STRUCT 16
DQ	2 dup (?)
XMMWORD	ENDS
ENDIF

.MODEL	FLAT
OPTION	DOTNAME
IF @Version LT 800
.text$	SEGMENT PAGE 'CODE'
ELSE
.text$	SEGMENT ALIGN(64) 'CODE'
ENDIF
ALIGN	16
_gcm_gmult_4bit_x86	PROC PUBLIC
$L_gcm_gmult_4bit_x86_begin::
	push	ebp
	push	ebx
	push	esi
	push	edi
	sub	esp,84
	mov	edi,DWORD PTR 104[esp]
	mov	esi,DWORD PTR 108[esp]
	mov	ebp,DWORD PTR [edi]
	mov	edx,DWORD PTR 4[edi]
	mov	ecx,DWORD PTR 8[edi]
	mov	ebx,DWORD PTR 12[edi]
	mov	DWORD PTR 16[esp],0
	mov	DWORD PTR 20[esp],471859200
	mov	DWORD PTR 24[esp],943718400
	mov	DWORD PTR 28[esp],610271232
	mov	DWORD PTR 32[esp],1887436800
	mov	DWORD PTR 36[esp],1822425088
	mov	DWORD PTR 40[esp],1220542464
	mov	DWORD PTR 44[esp],1423966208
	mov	DWORD PTR 48[esp],3774873600
	mov	DWORD PTR 52[esp],4246732800
	mov	DWORD PTR 56[esp],3644850176
	mov	DWORD PTR 60[esp],3311403008
	mov	DWORD PTR 64[esp],2441084928
	mov	DWORD PTR 68[esp],2376073216
	mov	DWORD PTR 72[esp],2847932416
	mov	DWORD PTR 76[esp],3051356160
	mov	DWORD PTR [esp],ebp
	mov	DWORD PTR 4[esp],edx
	mov	DWORD PTR 8[esp],ecx
	mov	DWORD PTR 12[esp],ebx
	shr	ebx,20
	and	ebx,240
	mov	ebp,DWORD PTR 4[ebx*1+esi]
	mov	edx,DWORD PTR [ebx*1+esi]
	mov	ecx,DWORD PTR 12[ebx*1+esi]
	mov	ebx,DWORD PTR 8[ebx*1+esi]
	xor	eax,eax
	mov	edi,15
	jmp	$L000x86_loop
ALIGN	16
$L000x86_loop:
	mov	al,bl
	shrd	ebx,ecx,4
	and	al,15
	shrd	ecx,edx,4
	shrd	edx,ebp,4
	shr	ebp,4
	xor	ebp,DWORD PTR 16[eax*4+esp]
	mov	al,BYTE PTR [edi*1+esp]
	and	al,240
	xor	ebx,DWORD PTR 8[eax*1+esi]
	xor	ecx,DWORD PTR 12[eax*1+esi]
	xor	edx,DWORD PTR [eax*1+esi]
	xor	ebp,DWORD PTR 4[eax*1+esi]
	dec	edi
	js	$L001x86_break
	mov	al,bl
	shrd	ebx,ecx,4
	and	al,15
	shrd	ecx,edx,4
	shrd	edx,ebp,4
	shr	ebp,4
	xor	ebp,DWORD PTR 16[eax*4+esp]
	mov	al,BYTE PTR [edi*1+esp]
	shl	al,4
	xor	ebx,DWORD PTR 8[eax*1+esi]
	xor	ecx,DWORD PTR 12[eax*1+esi]
	xor	edx,DWORD PTR [eax*1+esi]
	xor	ebp,DWORD PTR 4[eax*1+esi]
	jmp	$L000x86_loop
ALIGN	16
$L001x86_break:
	bswap	ebx
	bswap	ecx
	bswap	edx
	bswap	ebp
	mov	edi,DWORD PTR 104[esp]
	mov	DWORD PTR 12[edi],ebx
	mov	DWORD PTR 8[edi],ecx
	mov	DWORD PTR 4[edi],edx
	mov	DWORD PTR [edi],ebp
	add	esp,84
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_gcm_gmult_4bit_x86 ENDP
ALIGN	16
_gcm_ghash_4bit_x86	PROC PUBLIC
$L_gcm_ghash_4bit_x86_begin::
	push	ebp
	push	ebx
	push	esi
	push	edi
	sub	esp,84
	mov	ebx,DWORD PTR 104[esp]
	mov	esi,DWORD PTR 108[esp]
	mov	edi,DWORD PTR 112[esp]
	mov	ecx,DWORD PTR 116[esp]
	add	ecx,edi
	mov	DWORD PTR 116[esp],ecx
	mov	ebp,DWORD PTR [ebx]
	mov	edx,DWORD PTR 4[ebx]
	mov	ecx,DWORD PTR 8[ebx]
	mov	ebx,DWORD PTR 12[ebx]
	mov	DWORD PTR 16[esp],0
	mov	DWORD PTR 20[esp],471859200
	mov	DWORD PTR 24[esp],943718400
	mov	DWORD PTR 28[esp],610271232
	mov	DWORD PTR 32[esp],1887436800
	mov	DWORD PTR 36[esp],1822425088
	mov	DWORD PTR 40[esp],1220542464
	mov	DWORD PTR 44[esp],1423966208
	mov	DWORD PTR 48[esp],3774873600
	mov	DWORD PTR 52[esp],4246732800
	mov	DWORD PTR 56[esp],3644850176
	mov	DWORD PTR 60[esp],3311403008
	mov	DWORD PTR 64[esp],2441084928
	mov	DWORD PTR 68[esp],2376073216
	mov	DWORD PTR 72[esp],2847932416
	mov	DWORD PTR 76[esp],3051356160
ALIGN	16
$L002x86_outer_loop:
	xor	ebx,DWORD PTR 12[edi]
	xor	ecx,DWORD PTR 8[edi]
	xor	edx,DWORD PTR 4[edi]
	xor	ebp,DWORD PTR [edi]
	mov	DWORD PTR 12[esp],ebx
	mov	DWORD PTR 8[esp],ecx
	mov	DWORD PTR 4[esp],edx
	mov	DWORD PTR [esp],ebp
	shr	ebx,20
	and	ebx,240
	mov	ebp,DWORD PTR 4[ebx*1+esi]
	mov	edx,DWORD PTR [ebx*1+esi]
	mov	ecx,DWORD PTR 12[ebx*1+esi]
	mov	ebx,DWORD PTR 8[ebx*1+esi]
	xor	eax,eax
	mov	edi,15
	jmp	$L003x86_loop
ALIGN	16
$L003x86_loop:
	mov	al,bl
	shrd	ebx,ecx,4
	and	al,15
	shrd	ecx,edx,4
	shrd	edx,ebp,4
	shr	ebp,4
	xor	ebp,DWORD PTR 16[eax*4+esp]
	mov	al,BYTE PTR [edi*1+esp]
	and	al,240
	xor	ebx,DWORD PTR 8[eax*1+esi]
	xor	ecx,DWORD PTR 12[eax*1+esi]
	xor	edx,DWORD PTR [eax*1+esi]
	xor	ebp,DWORD PTR 4[eax*1+esi]
	dec	edi
	js	$L004x86_break
	mov	al,bl
	shrd	ebx,ecx,4
	and	al,15
	shrd	ecx,edx,4
	shrd	edx,ebp,4
	shr	ebp,4
	xor	ebp,DWORD PTR 16[eax*4+esp]
	mov	al,BYTE PTR [edi*1+esp]
	shl	al,4
	xor	ebx,DWORD PTR 8[eax*1+esi]
	xor	ecx,DWORD PTR 12[eax*1+esi]
	xor	edx,DWORD PTR [eax*1+esi]
	xor	ebp,DWORD PTR 4[eax*1+esi]
	jmp	$L003x86_loop
ALIGN	16
$L004x86_break:
	bswap	ebx
	bswap	ecx
	bswap	edx
	bswap	ebp
	mov	edi,DWORD PTR 112[esp]
	lea	edi,DWORD PTR 16[edi]
	cmp	edi,DWORD PTR 116[esp]
	mov	DWORD PTR 112[esp],edi
	jb	$L002x86_outer_loop
	mov	edi,DWORD PTR 104[esp]
	mov	DWORD PTR 12[edi],ebx
	mov	DWORD PTR 8[edi],ecx
	mov	DWORD PTR 4[edi],edx
	mov	DWORD PTR [edi],ebp
	add	esp,84
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_gcm_ghash_4bit_x86 ENDP
ALIGN	16
__mmx_gmult_4bit_inner	PROC PRIVATE
	xor	ecx,ecx
	mov	edx,ebx
	mov	cl,dl
	shl	cl,4
	and	edx,240
	movq	mm0,QWORD PTR 8[ecx*1+esi]
	movq	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 14[edi]
	psllq	mm2,60
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 13[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 12[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 11[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 10[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 9[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 8[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 7[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 6[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 5[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 4[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 3[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 2[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR 1[edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	mov	cl,BYTE PTR [edi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	mov	edx,ecx
	movd	ebx,mm0
	pxor	mm0,mm2
	shl	cl,4
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[ecx*1+esi]
	psllq	mm2,60
	and	edx,240
	pxor	mm1,QWORD PTR [ebp*8+eax]
	and	ebx,15
	pxor	mm1,QWORD PTR [ecx*1+esi]
	movd	ebp,mm0
	pxor	mm0,mm2
	psrlq	mm0,4
	movq	mm2,mm1
	psrlq	mm1,4
	pxor	mm0,QWORD PTR 8[edx*1+esi]
	psllq	mm2,60
	pxor	mm1,QWORD PTR [ebx*8+eax]
	and	ebp,15
	pxor	mm1,QWORD PTR [edx*1+esi]
	movd	ebx,mm0
	pxor	mm0,mm2
	mov	edi,DWORD PTR 4[ebp*8+eax]
	psrlq	mm0,32
	movd	edx,mm1
	psrlq	mm1,32
	movd	ecx,mm0
	movd	ebp,mm1
	shl	edi,4
	bswap	ebx
	bswap	edx
	bswap	ecx
	xor	ebp,edi
	bswap	ebp
	ret
__mmx_gmult_4bit_inner ENDP
ALIGN	16
_gcm_gmult_4bit_mmx	PROC PUBLIC
$L_gcm_gmult_4bit_mmx_begin::
	push	ebp
	push	ebx
	push	esi
	push	edi
	mov	edi,DWORD PTR 20[esp]
	mov	esi,DWORD PTR 24[esp]
	call	$L005pic_point
$L005pic_point:
	pop	eax
	lea	eax,DWORD PTR ($Lrem_4bit-$L005pic_point)[eax]
	movzx	ebx,BYTE PTR 15[edi]
	call	__mmx_gmult_4bit_inner
	mov	edi,DWORD PTR 20[esp]
	emms
	mov	DWORD PTR 12[edi],ebx
	mov	DWORD PTR 4[edi],edx
	mov	DWORD PTR 8[edi],ecx
	mov	DWORD PTR [edi],ebp
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_gcm_gmult_4bit_mmx ENDP
ALIGN	16
_gcm_ghash_4bit_mmx	PROC PUBLIC
$L_gcm_ghash_4bit_mmx_begin::
	push	ebp
	push	ebx
	push	esi
	push	edi
	mov	ebp,DWORD PTR 20[esp]
	mov	esi,DWORD PTR 24[esp]
	mov	edi,DWORD PTR 28[esp]
	mov	ecx,DWORD PTR 32[esp]
	call	$L006pic_point
$L006pic_point:
	pop	eax
	lea	eax,DWORD PTR ($Lrem_4bit-$L006pic_point)[eax]
	add	ecx,edi
	mov	DWORD PTR 32[esp],ecx
	sub	esp,20
	mov	ebx,DWORD PTR 12[ebp]
	mov	edx,DWORD PTR 4[ebp]
	mov	ecx,DWORD PTR 8[ebp]
	mov	ebp,DWORD PTR [ebp]
	jmp	$L007mmx_outer_loop
ALIGN	16
$L007mmx_outer_loop:
	xor	ebx,DWORD PTR 12[edi]
	xor	edx,DWORD PTR 4[edi]
	xor	ecx,DWORD PTR 8[edi]
	xor	ebp,DWORD PTR [edi]
	mov	DWORD PTR 48[esp],edi
	mov	DWORD PTR 12[esp],ebx
	mov	DWORD PTR 4[esp],edx
	mov	DWORD PTR 8[esp],ecx
	mov	DWORD PTR [esp],ebp
	mov	edi,esp
	shr	ebx,24
	call	__mmx_gmult_4bit_inner
	mov	edi,DWORD PTR 48[esp]
	lea	edi,DWORD PTR 16[edi]
	cmp	edi,DWORD PTR 52[esp]
	jb	$L007mmx_outer_loop
	mov	edi,DWORD PTR 40[esp]
	emms
	mov	DWORD PTR 12[edi],ebx
	mov	DWORD PTR 4[edi],edx
	mov	DWORD PTR 8[edi],ecx
	mov	DWORD PTR [edi],ebp
	add	esp,20
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_gcm_ghash_4bit_mmx ENDP
ALIGN	64
$Lrem_4bit::
DD	0,0,0,29491200,0,58982400,0,38141952
DD	0,117964800,0,113901568,0,76283904,0,88997888
DD	0,235929600,0,265420800,0,227803136,0,206962688
DD	0,152567808,0,148504576,0,177995776,0,190709760
DB	71,72,65,83,72,32,102,111,114,32,120,56,54,44,32,67
DB	82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112
DB	112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62
DB	0
.text$	ENDS
END
