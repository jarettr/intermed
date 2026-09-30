# Layer M Domain Model Fixes — Implementation Summary

## Обзор

Реализованы все 11 исправлений доменных моделей Layer M для устранения проблем с semantic_hash, канонической формой JSON и метаданными summary.

## Реализованные изменения

### 1. Схема кеша и версии парсеров

- **RESOURCE_AST_CACHE_SCHEMA**: v5 → v6 (инвалидация старого кеша)
- **genjson**: r3 → r4 (для совместимости с новой канонической формой)

### 2. canonicalize_json (mod.rs)

**Проблема**: Функция сортировала массивы, что ломало порядок элементов в структурных ресурсах (loot tables, shaped recipes).

**Решение**: Удалена сортировка массивов, оставлена только рекурсивная обработка для сортировки ключей объектов (через BTreeMap).

```rust
// Теперь canonicalize_json НЕ сортирует массивы
fn canonicalize_json(val: &mut serde_json::Value) {
    match val {
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                canonicalize_json(v);  // Рекурсивно, но без сортировки
            }
        }
        Value::Object(obj) => {
            for v in obj.values_mut() {
                canonicalize_json(v);
            }
        }
        _ => {}
    }
}
```

### 3. TagSummary (tag.rs)

**Версия**: tag-r1 → tag-r2

**Изменения**:
- `entries: Vec<String>` → `entries: Vec<TagEntrySummary>`
- Добавлена структура `TagEntrySummary` с полями:
  - `id: String` — идентификатор записи
  - `is_tag: bool` — флаг тега
  - `required: bool` — флаг обязательности (эффективное значение, true по умолчанию)

**Причина**: Старый формат терял метаданные о флагах `is_tag` и `required`, что ломало точный анализ зависимостей.

### 4. ModelSummary (model.rs)

**Версия**: model-r1 → model-r2

**Изменения**:
- Удалены поля `texture_count` и `override_count`
- Добавлены:
  - `textures: BTreeMap<String, String>` — полный маппинг текстур (slot → id)
  - `overrides_fingerprint: Option<String>` — SHA256 массива overrides (порядок важен)

**Причина**: Счетчики не позволяли различать модели с разными текстурными маппингами или overrides.

### 5. BlockstateSummary (blockstate.rs)

**Версия**: blockstate-r2 → blockstate-r3

**Изменения**:
- Исправлена генерация `variant_fingerprint` для multipart блоков
- Теперь используется хеш `when` условия вместо индекса `multipart[i]`
- Формат: `{when_hash_prefix}|model|rot|uvlock|weight`

**Причина**: Старый подход с индексами давал разные fingerprints при переупорядочивании multipart случаев с идентичной семантикой.

### 6. LootTableSummary (loot_table.rs)

**Версия**: loot-table-r2 → loot-table-r3

**Изменения**:
- Добавлено поле `structure_fingerprint: String` — SHA256 всего массива pools

**Причина**: Порядок pools и entries имеет значение (first match wins), но старый summary хранил только `drops`, теряя структурную информацию.

### 7. AtlasSummary (atlas.rs)

**Версия**: atlas-r2 → atlas-r3

**Изменения**:
- Дескрипторы источников теперь содержат полный канонический JSON объекта
- Формат: `single:{canonical_json}` или `{type}:{canonical_json}`

**Причина**: Старый формат `directory:block` был слишком сокращенным и терял детали конфигурации источников.

### 8. AdvancementSummary (advancement.rs)

**Версия**: advancement-r2 → advancement-r3

**Изменения**:
- Поле `parent` теперь использует новое отношение `ParentAdvancement` вместо `AdvancementCriterion`
- Поле `rewards.recipes` использует новое отношение `UnlocksRecipe` вместо `UsesItem`

**Причина**: `AdvancementCriterion` было неправильной семантикой для parent ссылок.

### 9. RecipeSummary (recipe.rs)

**Версия**: recipe-r3 → recipe-r4

**Причина**: Версия повышена для согласованности, хотя структурных изменений summary не было (fingerprint логика остается через `custom_payload_hash`).

### 10. RefRelation enum (model.rs)

**Добавленные варианты**:
- `ParentAdvancement` — ссылка на родительский advancement (`parent` field)
- `UnlocksRecipe` — advancement открывает рецепт (`rewards.recipes`)
- `AdvancementCriterion` — deprecated, оставлен для совместимости

**Обновления**:
- `as_str()` — добавлены строковые представления
- `implies_dependency()` — ParentAdvancement и UnlocksRecipe считаются зависимостями
- Обновлены все exhaustive matches в refs.rs, facts.rs, rule.rs

### 11. Worldgen is_tag flag (registry_spec.rs)

**Изменение**: Исправлена функция `push_id` для установки `is_tag` ПЕРЕД вызовом `trim_start_matches('#')`.

```rust
let is_tag = id.starts_with('#');
let target = id.trim_start_matches('#').to_string();
```

**Причина**: Старый код терял информацию о префиксе `#` до проверки флага.

### 12. SAFE_DANGLING_RELATIONS (rule.rs)

**Изменение**: `["loot_entry", "advancement_criterion", "uses_tag"]` → `["loot_entry", "parent_advancement", "uses_tag"]`

**Причина**: `advancement_criterion` заменен на `parent_advancement` для корректной обработки dangling references.

## Обновления тестов

### Diff tests (diff.rs)
- Обновлены конструкторы ModelSummary для использования BTreeMap и Option<String>
- Обновлены конструкторы LootTableSummary с `structure_fingerprint`
- Обновлены конструкторы TagSummary с `Vec<TagEntrySummary>`

### Refs tests (refs.rs)
- Функция `tag_record` теперь создает `TagEntrySummary` объекты
- Обновлена логика извлечения `tag_entries` для преобразования в `Vec<String>`

### Facts tests (facts.rs)
- Обновлена логика для ModelSummary: `s.textures.len()` вместо `s.texture_count`
- Добавлена обработка `overrides_fingerprint`

### Model tests (model.rs)
- `s.texture_count` → `s.textures.len()`

### Golden fixtures
Обновлены файлы:
- `tag_basic.json.golden` — entries теперь содержат полные объекты
- `model.json.golden` — textures теперь BTreeMap

## Property tests

Все property tests прошли успешно:
- `parse_never_panics_on_arbitrary_bytes`
- `parse_never_panics_on_arbitrary_json`
- `recipe_semantic_hash_is_order_independent` ✅
- `tag_entries_are_a_canonical_set` ✅

**Важно**: Тесты на order-independence проходят благодаря тому, что summary структуры сортируют set-like поля (outputs, ingredients, entries).

## Результаты

✅ **Все 114 unit tests** в intermed-resource-ast прошли
✅ **Все property tests** прошли
✅ **Все workspace tests** прошли
✅ **Golden fixtures** обновлены
✅ **Компиляция всего workspace** успешна

## Миграция

Старые cached AST автоматически инвалидируются благодаря:
1. Изменению `RESOURCE_AST_CACHE_SCHEMA` (v5 → v6)
2. Изменению `parser_version()` через обновленные версии доменов

Пользователям не требуется никаких действий — кеш будет автоматически пересоздан при следующем запуске.

## Влияние на производительность

Минимальное. Основные изменения:
- BTreeMap вместо счетчиков для ModelSummary (O(n log n) вместо O(n), но n мало)
- Дополнительные SHA256 хеши для structure fingerprints (амортизируются кешированием)
- Более полные summary структуры (незначительное увеличение размера кеша)

## Обратная совместимость

**Breaking changes**:
- Изменен формат cached AST (требуется перестроение кеша)
- Изменены типы полей в public API (TagSummary, ModelSummary, etc.)
- Добавлены новые RefRelation варианты

**Не breaking**:
- Старые файлы данных (JSON) парсятся без изменений
- Логика анализа остается обратно совместимой
- Deprecated `AdvancementCriterion` остается для совместимости
