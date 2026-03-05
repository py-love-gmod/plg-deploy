# В разработке

Задачи:
- [ ] Сборка аддона
- [ ] Упаковка в gma
- [ ] Деплой в стим

Необходимо создать менеджер хоть каких-то дополнительных ресурсов, а то жопа будет.

```yml
steps:
    - uses: actions/checkout@v4

    - uses: py-love-gmod/plg-deploy@v1
      with:
        workshop-id: "1234567890"
      secrets:
        STEAM_USER: ${{ secrets.STEAM_USER }}
        STEAM_PASS: ${{ secrets.STEAM_PASS }}
```
