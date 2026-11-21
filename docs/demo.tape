# Regrava docs/demo.gif (usado no README). Rodar da raiz do projeto, com a venv já criada:
#
#   vhs docs/demo.tape
#
# (precisa do VHS: https://github.com/charmbracelet/vhs — `brew install vhs`)

Output docs/demo.gif

Set Shell "zsh"
Set FontSize 19
Set FontFamily "Menlo"
Set Width 1040
Set Height 620
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 45ms
Set WindowBar Colorful

Hide
Type "source .venv/bin/activate && clear"
Enter
Sleep 1s
Show

Type "sentinela revisar tests/exemplos/multiplos.diff"
Sleep 600ms
Enter
Sleep 4500ms

Type "sentinela revisar tests/exemplos/multiplos.diff --nota"
Sleep 600ms
Enter
Sleep 5500ms
