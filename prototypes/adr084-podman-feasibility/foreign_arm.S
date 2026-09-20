.syntax unified
.arm
.section .text
.global _start
.type _start, %function
_start:
    mov r7, #20
    svc #0
    mov r7, #1
    mov r0, #90
    svc #0
.size _start, .-_start
