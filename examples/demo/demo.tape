# The output shown is replayed from a real run on a kind cluster. To regenerate,
# from the repo root:
#   examples/demo/capture.sh
#   docker run --rm -v "$PWD:/vhs" ghcr.io/charmbracelet/vhs examples/demo/demo.tape
Output examples/demo/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1280
Set Height 740
Set Padding 16
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"

Hide
Type "source examples/demo/replay.sh"
Enter
Sleep 500ms
Show

Type "kubectl get networkpolicy -n shop"
Enter
Sleep 2s
Type "kubectl apply -f generator.yaml"
Enter
Sleep 1s
Type "kubectl get networkpolicygenerator -n shop"
Enter
Sleep 2s
Type "kubectl get networkpolicy -n shop"
Enter
Sleep 3s

Hide
Type "clear"
Enter
Sleep 300ms
Show

Type "kubectl describe networkpolicy -n shop"
Enter
Sleep 6s
