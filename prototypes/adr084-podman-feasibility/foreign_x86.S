.section .text
.global _start
.type _start, @function
_start:
    mov $20, %eax
    int $0x80
    mov $1, %eax
    mov $90, %ebx
    int $0x80
.size _start, .-_start
