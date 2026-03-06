Kubernetes Manifests — Tech Challenge 3

Este diretório contém todos os manifestos Kubernetes responsáveis pelo deploy dos microsserviços da aplicação no cluster Amazon EKS.

Ele representa a fonte de verdade da infraestrutura de deploy (GitOps) dentro do monorepo.
Qualquer alteração nestes arquivos é automaticamente detectada pelo ArgoCD, que sincroniza o estado desejado com o cluster Kubernetes.
