
; usage in .cpp file 
; extern "C" void x86ShellCode()
;
; Description: The following demonstrates calling LoadLibraryA using shellcode in x86:
; HMODULE WINAPI LoadLibrary( _In_ LPCTSTR lpFileName );
;

.MODEL flat,c

EXTERNDEF ReturnEip: DWORD

.CODE

x86ShellCode proc	

	; Save Registers
	PUSHAD
	PUSHFD
			
    ; Trick To Grab RIP
	call	next
next:
	pop		EAX
    ;add EAX, 5    ; Only here for reference, for other projects.
   
    ; Save EIP in EBX
	mov		EBX, EAX

    ; Address of DLL Name
	mov		EAX, string - next    ; Offset To "string label" Below
	movzx	EAX, AL               ; Do This To Avoid Possible Negative Values (Due To Sign Extend)
	add		EAX, EBX              ; Offset
	push    EAX                   ; Send to stack 

    ; Address of LoadLibraryA
	mov		EAX, func - next      ; Offset To "func" Var Below
	movzx	EAX, AL               ; Do This To Avoid Possible Negative Values (Due To Sign Extend)
	add		EAX, EBX              ; Pointer Acquired In EAX
	mov		EAX, [EAX]            ; Deref To Access Address For LoadLibraryA()
	call	EAX                   ; Call LoadLibraryA()
	
	; Replace Registers
	POPFD
	POPAD
	
	JMP ReturnEip	
	
x86ShellCode endp

func DWORD 0BEBADEC0h
string: 

end