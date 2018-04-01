
.CODE

; usage in .cpp file 
; extern "C" void x64ShellCode()
;
; Description: The following demonstrates calling LoadLibraryA using shellcode in x64:
; HMODULE WINAPI LoadLibrary( _In_ LPCTSTR lpFileName );
;

x64ShellCode proc	

	; Save Registers
	PUSHFQ
	PUSH RAX	
	PUSH RCX    
	PUSH RDX    
	PUSH RBX	
	PUSH RBP    
	PUSH RSI    
	PUSH RDI		
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15
	
	; Extra because of calls below, the calls wipe out the last two stack values
	; So, we push 2 extra values because of this
	PUSH R14
	PUSH R15

    ; Trick To Grab RIP
	call	next
next:
	pop		RAX
    ;add RAX, 5    ; Only here for reference, for other projects.
   
    ; Save RIP in RBX
	mov		RBX, RAX

    ; Address of DLL Name
	mov		RCX, string - next    ; Offset To "string label" Below
	movzx	RCX, CX               ; Do This To Avoid Possible Negative Values (Due To Sign Extend)
	add		RCX, RBX              ; Address Acquired In RCX	

    ; Address of LoadLibraryA
	mov		RAX, func - next      ; Offset To "func" Var Below
	movzx	RAX, AX               ; Do This To Avoid Possible Negative Values (Due To Sign Extend)
	add		RAX, RBX              ; Pointer Acquired In RAX
	mov		RAX, [RAX]            ; Deref To Access Address For LoadLibraryA()
	call	RAX                   ; Call LoadLibraryA()
	add     RSP, 10h              ; Clean up stack, From LoadLibrary Call ... 2 items.

	; Replace Registers
	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8 	
	POP RDI
	POP RSI
	POP RBP	
	POP RBX
	POP RDX
	POP RCX
	POP RAX
	POPFQ
		
	push Return
	ret

x64ShellCode endp

func QWORD 0ED55CEACBEBADEC0h
Return QWORD 0ED55CEACBEBADEC0h
string: 

end