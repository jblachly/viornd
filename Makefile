CC=gcc
CLANG=clang
SRC=viornd.c
OBJ=viornd.o
MOD=viornd

FFLAGS=-fident -finline -fno-inline-functions -fno-builtin -fno-asm -fdiagnostics-show-option -fno-strict-aliasing -fno-unit-at-a-time -fno-optimize-sibling-calls -ffreestanding -fno-inline-small-functions -fno-inline-functions-called-once -fno-ipa-cp -fstack-protector -ffreestanding
DEFINES=-D__sun -D_ASM_INLINES -D_KERNEL -D_SYSCALL32 -D_SYSCALL32_IMPL -D_ELF64 -D_DDI_STRICT -Dsun -D__sun -D__SVR4 -DDEBUG
UNDEFS=-Ui386 -U__i386
WHATEVER=-nodefaultlibs -m64 -mtune=opteron -O2 -mno-red-zone -mno-mmx -mno-sse -msave-args -gdwarf-2 -std=gnu99 -msave-args -mcmodel=kernel
# -nostdinc

# -msave-args is illumos GCC specific
# -gdwarf2 -> -g
WHATEVER_CLANG=-nodefaultlibs -m64 -mtune=opteron -O2 -mno-red-zone -mno-mmx -mno-sse -g -std=gnu99 -mcmodel=kernel
WFLAGS=-Wall -Wextra -Werror -Wno-missing-braces -Wno-sign-compare -Wno-unknown-pragmas -Wno-unused-parameter -Wno-missing-field-initializers -Wno-unused-function
INCLUDES=-I../illumos-gate/usr/src/uts/common/io/virtio/

all:	$(MOD) $(OBJ) $(SRC)
clean:
	rm $(MOD) $(OBJ)

# /opt/gcc/4.4.4/bin/gcc -fident -finline -fno-inline-functions -fno-builtin -fno-asm -fdiagnostics-show-option -nodefaultlibs -D__sun -m64 -mtune=opteron -Ui386 -U__i386 -fno-strict-aliasing -fno-unit-at-a-time -fno-optimize-sibling-calls -O2 -D_ASM_INLINES -ffreestanding -mno-red-zone -mno-mmx -mno-sse -msave-args -Wall -Wextra -gdwarf-2 -std=gnu99 -msave-args -Werror -Wno-missing-braces -Wno-sign-compare -Wno-unknown-pragmas -Wno-unused-parameter -Wno-missing-field-initializers -Wno-unused-function -fno-inline-small-functions -fno-inline-functions-called-once -fno-ipa-cp -fstack-protector -I../../../common/crypto -D_KERNEL -ffreestanding -D_SYSCALL32 -D_SYSCALL32_IMPL -D_ELF64 -D_DDI_STRICT -Dsun -D__sun -D__SVR4 -DDEBUG -I../../i86pc -I../../intel -nostdinc -I../../common -c -o debug64/swrand.o ../../common/crypto/io/swrand.c -mcmodel=kernel
$(OBJ): $(SRC)
	$(CC) $(FFLAGS) $(DEFINES) $(UNDEFS) $(WHATEVER) $(WFLAGS) $(INCLUDES) -c -o $(OBJ) $(SRC)
	$(CLANG) -fsanitize=address $(DEFINES) $(UNDEFS) $(WHATEVER_CLANG) $(INCLUDES) -c -o viornd_clang.o $(SRC)
# /home/james/illumos-gate/usr/src/tools/proto/root_i386-nd/opt/onbld/bin/i386/ctfconvert -i -L VERSION debug64/swrand.o

# /usr/ccs/bin/ld -r -dy -Nmisc/kcf -Nmisc/sha1 -o debug64/swrand debug64/swrand.o
$(MOD): $(OBJ)
	/usr/bin/ld -r -dy -Nmisc/virtio -Nmisc/kcf -o $(MOD) $(OBJ)
