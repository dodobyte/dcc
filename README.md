# Dcc - A Toy C Compiler

This was my first compiler attempt. In retrospect, i should have picked a smaller language. Although it's very flawed, there are some good parts. The poorest part is the code generation.

It's pure C and produces X86 Windows PE executable independently of any third party software such as assembler or linker. Parsing is done with a mix of Recursive Descent Parser and operator-precedence parser (Shunting Yard).

Assembler is very limited and linker generates import table only for C standard library (msvcrt.dll).

## implemented subset
- Arbitrarily nested if-else for while
- Recursive calls
- Basic pointer access
- int and char types (pointers included)
- String literals

Pointer arithmetic and preprocessor are not implemented along with many other features. Take a look at the examples.

See the [article](http://dogankurt.com/dcc.html) for more information.
