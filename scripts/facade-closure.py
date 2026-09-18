#!/usr/bin/env python3
"""СТОРОЖ ЗАМКНУТОСТИ ФАСАДА: имя, стоящее в публичной подписи `reflex`, обязано называться через
`reflex`.

ЗАКОН, КОТОРЫЙ ОН ДЕРЖИТ. Фасад обещает «потребитель зависит от ОДНОГО крейта». Обещание ломается
не тем, что на фасаде мало имён (их там ровно столько, сколько дверей), а тем, что дверь ТРЕБУЕТ
назвать тип, которого сама не отдаёт: цепочка собирается, `impl` пишется, а `let _: ??? = ...`
написать нечем — и автор берёт вторую зависимость. Замкнутость по подписи и есть проверяемая форма
обещания.

ПОЧЕМУ RUSTDOC, А НЕ ГРЕП. Греп видит ПУТЬ (`reflex_core::Tap` в сигнатуре) и слеп к тому, как
течёт на деле: тип приезжает приватным `use` в шапке файла и стоит в подписи голым именем. На
18.09.2026 греп по путям находил ОДНУ течь из двадцати четырёх; остальные двадцать три были
невидимы — включая весь словарь носителя (`Held`, `Terminal`, `Serves`, `Delivered`...), которым
наш собственный `reflex-windivert` брал `reflex-core` второй зависимостью. Разбор идёт по тому же
дереву, что видит компилятор: `--output-format json`.

ЦЕНА, УЖЕ ОПЛАЧЕННАЯ ГЛАЗАМИ. Шесть реэкспортов фасада заведены докблоками вида «нашлось при
попытке поверить свой же транспорт»: течь ловилась ровно тогда, когда кто-то мимо шёл. Шесть раз
подряд — это не череда случайностей, а отсутствующая проверка.

ЧЕГО ОН НЕ МЕРИТ. Он не судит, ДОЛЖНА ли дверь быть публичной: подпись, которую стоило бы закрыть,
он потребует замкнуть реэкспортом. Он не видит имён, нужных потребителю, но в подписях НЕ стоящих
(прибор парка, не выставленный на фасад, — законная находка не для него). И он молчит о чужих
крейтах (`std`, `smallvec`): чужое имя потребитель называет своей зависимостью законно.
"""

import json
import sys
from collections import defaultdict

# Крейты дерева: их имена потребитель называть НЕ обязан — за тем и фасад.
OURS = {
    "reflex_core",
    "reflex_engine",
    "reflex_instrument",
    "reflex_linux",
    "reflex_os",
    "reflex_runtime",
    "reflex_windivert",
}

# Файлы, чьи объявления считаются дверью. Подпись, объявленная в чужом крейте (слепой `impl` из
# `core`, накрывающий тип фасада), к двери не относится — замыкать её реэкспортом нечего.
DOOR = "reflex/src/"


def nameable_ids(index, root):
    """Всё, что достижимо от корня фасада: свои объявления и цели публичных `use`."""
    seen_modules = set()
    found = set()

    def walk(module_id):
        if module_id in seen_modules:
            return
        seen_modules.add(module_id)
        item = index.get(module_id)
        if not item or "module" not in item["inner"]:
            return
        for child_id in item["inner"]["module"]["items"]:
            found.add(child_id)
            child = index.get(child_id)
            if not child:
                continue
            if "module" in child["inner"]:
                walk(child_id)
            elif "use" in child["inner"]:
                target = child["inner"]["use"].get("id")
                if target is not None:
                    found.add(target)
                    walk(target)

    walk(root)

    # Поля, варианты и методы называемого типа называемы вместе с ним — своим именем их никто не
    # импортирует, а в подписях они стоят.
    growing = True
    while growing:
        growing = False
        for item_id in list(found):
            item = index.get(item_id)
            if not item:
                continue
            inner = item["inner"]
            children = []
            if "struct" in inner:
                kind = inner["struct"]["kind"]
                if isinstance(kind, dict) and "plain" in kind:
                    children += kind["plain"]["fields"]
                elif isinstance(kind, dict) and "tuple" in kind:
                    children += [f for f in kind["tuple"] if f]
                children += inner["struct"].get("impls", [])
            elif "enum" in inner:
                children += inner["enum"]["variants"] + inner["enum"].get("impls", [])
            elif "trait" in inner:
                children += inner["trait"]["items"] + inner["trait"].get("implementations", [])
            elif "impl" in inner:
                children += inner["impl"]["items"]
            for child_id in children:
                if child_id not in found:
                    found.add(child_id)
                    growing = True
    return found


def referenced_ids(node, out):
    """Идентификаторы типов, стоящих в куске подписи."""
    if isinstance(node, list):
        for child in node:
            referenced_ids(child, out)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in ("resolved_path", "qualified_path"):
            if "id" in value:
                out.add(value["id"])
            referenced_ids(value.get("args"), out)
            referenced_ids(value.get("self_type"), out)
            referenced_ids(value.get("trait"), out)
        elif key == "id" and isinstance(value, int):
            out.add(value)
        else:
            referenced_ids(value, out)


def signature_of(inner):
    """Подпись предмета — ВМЕСТЕ С ограничениями: `S: Word` требует назвать `Word` ровно так же,
    как довод требует назвать свой тип. Без обхода ограничений замер занижен вдвое (проверено:
    11 течей против 24)."""
    if "function" in inner:
        return [inner["function"]["sig"], inner["function"].get("generics")]
    if "struct_field" in inner:
        return inner["struct_field"]
    if "type_alias" in inner:
        return inner["type_alias"]["type"]
    if "constant" in inner:
        return inner["constant"]["type"]
    if "struct" in inner:
        return inner["struct"].get("generics")
    if "enum" in inner:
        return inner["enum"].get("generics")
    if "trait" in inner:
        return [inner["trait"].get("generics"), inner["trait"].get("bounds")]
    if "impl" in inner:
        return [inner["impl"].get("generics"), inner["impl"].get("trait"), inner["impl"].get("for")]
    if "assoc_type" in inner:
        return [inner["assoc_type"].get("bounds"), inner["assoc_type"].get("type")]
    return None


def main(path):
    doc = json.load(open(path))
    index = {int(k): v for k, v in doc["index"].items()}
    paths = {int(k): v for k, v in doc["paths"].items()}
    nameable = nameable_ids(index, doc["root"])

    leaks = defaultdict(list)
    for item_id in sorted(nameable):
        item = index.get(item_id)
        if not item:
            continue
        signature = signature_of(item["inner"])
        span = item.get("span")
        if signature is None or not span or not span["filename"].startswith(DOOR):
            continue
        refs = set()
        referenced_ids(signature, refs)
        for ref in refs:
            if ref in nameable or ref not in paths:
                continue
            path_parts = paths[ref]["path"]
            if path_parts[0] in OURS:
                where = f"{span['filename']}:{span['begin'][0]}"
                leaks["::".join(path_parts)].append((item.get("name") or str(item_id), where))

    if not leaks:
        print(f"дверь замкнута: {len(nameable)} имён, течей нет")
        return 0

    print("ТЕЧЬ ДВЕРИ: тип дерева стоит в публичной подписи фасада, но фасадом не назван\n")
    for name, sites in sorted(leaks.items(), key=lambda kv: -len(kv[1])):
        first_name, first_where = sites[0]
        print(f"  {name:<52} {len(sites):>3}  напр. {first_name} @ {first_where}")
    print(
        "\nЛечится одним из двух: реэкспортом на фасаде (имя нужно потребителю) либо закрытием\n"
        "подписи (имя нужно нам). Третьего — «потребитель возьмёт вторую зависимость» — нет."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
