.globl setup
.globl executioner

.data
id: .long 0
jmptofake: .quad 0

.text

setup:
	movl $0, id(%rip)
	mov %ecx, id(%rip)
	movq $0, jmptofake(%rip)
	mov %rdx, jmptofake(%rip)
	ret

executioner:
	mov %rcx, %r10
	mov id(%rip), %eax
	jmp *jmptofake(%rip)
	ret
