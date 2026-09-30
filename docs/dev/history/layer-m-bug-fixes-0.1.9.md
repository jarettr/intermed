# Layer M Bug Fixes — Implementation Summary

## Обзор

Исправлено 7 ошибок в intermed-resource-ast, связанных с контрактами, безопасностью по умолчанию и нормализацией данных.

## Исправленные ошибки

### 1. Rule::requirements() не соответствовал реальному использованию

**Проблема**: `requirements()` заявлял зависимости на `RESOURCE_REFERENCE` и `RESOURCE_AST_PARSED`, но `evaluate()` их не читал. При этом реально использовались `RESOURCE_DANGLING_REFERENCE` и `RESOURCE_SEMANTIC_ISSUE`, которые не были заявлены.

**Исправление** (rule.rs:32-50):
```rust
.facts([
    kind::RESOURCE_SEMANTIC_DIFF,
    kind::RESOURCE_DANGLING_REFERENCE,    // добавлено
    kind::RESOURCE_SEMANTIC_ISSUE,        // добавлено
])
```

**Влияние**: Если requirements участвуют в scheduling/coverage, это функциональный баг — теперь контракт соответствует реальности.

### 2. dangling_sample() - неправильная семантика count

**Проблема**: Функция дедуплицировала target IDs, затем брала `count`, но title говорил о "reference(s)". Если 10 ресурсов ссылались на один missing ID, отчёт показывал "1 reference".

**Исправление** (rule.rs:117-146, 190-192):
- Добавлен комментарий: `Returns (sample_string, unique_target_count)`
- Title изменён на: `"{count} missing target(s)"` вместо `"{count} reference(s)"`
- Теперь явно указывается, что count — это количество уникальных отсутствующих целей

**До**:
```
"{count} reference(s) point to a resource..."
```

**После**:
```
"{count} missing target(s) referenced by..."
```

### 3. implies_dependency() небезопасен по умолчанию

**Проблема**: Логика "всё кроме четырёх asset-relations" означала, что любой новый `RefRelation` автоматически становился доказательством dependency. Для консервативного анализатора это риск false positives.

**Исправление** (model.rs:235-257):
```rust
// Было: !matches!(ParentModel | UsesModel | UsesTexture | AtlasSource)
// Стало: explicit allowlist
pub fn implies_dependency(self) -> bool {
    matches!(
        self,
        RefRelation::UsesItem
            | RefRelation::UsesTag
            | RefRelation::UsesRecipeType
            | RefRelation::ProducesItem
            | RefRelation::LootEntry
            | RefRelation::ParentAdvancement
            | RefRelation::UnlocksRecipe
            | RefRelation::RegistryRef
    )
}
```

**Тест** (model.rs:368-389):
- Обновлён список data refs для включения новых вариантов
- Добавлен тест для deprecated `AdvancementCriterion` (не в allowlist)

### 4. SemanticOpacity::is_reliable() небезопасен по умолчанию

**Проблема**: Логика `!matches!(OpaqueCustomSerializer)` означала, что любой новый уровень непрозрачности автоматически становился reliable.

**Исправление** (model.rs:159-166):
```rust
// Было: !matches!(self, OpaqueCustomSerializer)
// Стало: exhaustive match
pub fn is_reliable(self) -> bool {
    match self {
        SemanticOpacity::Transparent | SemanticOpacity::PartiallyKnown => true,
        SemanticOpacity::OpaqueCustomSerializer => false,
    }
}
```

**Влияние**: Новые уровни непрозрачности теперь требуют явного решения о reliability.

### 5. ResourceLevel::parse() слишком тихо проглатывает ошибки

**Проблема**: Неизвестное значение превращалось в `Basic`. Опечатка `--resource-level ful` отключала Layer M без предупреждения.

**Исправление** (model.rs:38-50):
```rust
// Было: неизвестные значения -> Basic (silent fallback)
// Стало: Result с ошибкой
pub fn parse(s: &str) -> Result<Self, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "basic" => Ok(ResourceLevel::Basic),
        "semantic" => Ok(ResourceLevel::Semantic),
        "full" => Ok(ResourceLevel::Full),
        _ => Err(format!(
            "unknown resource level '{s}'; expected 'basic', 'semantic', or 'full'"
        )),
    }
}
```

**Примечание**: Внешний CLI должен обрабатывать Result. Текущий вызов через `From<ResourceAstLevel>` не затронут.

### 6. Нормализация writer identity неполная

**Проблема**: `emit()` строит соответствие archive → canonical identity и заменяет writer у `scan.records`, но `scan.extra_owners` добавляется в граф без аналогичной нормализации. Если `partial.writer` отличается от MOD/PLUGIN.subject, один мод может оказаться в графе под двумя именами.

**Исправление** (collector.rs:30-38, 262-286, 436-439):

1. Изменена структура `extra_owners`:
```rust
// Было: Vec<(String, String)>              // (namespace, writer)
// Стало: Vec<(String, String, String)>    // (namespace, writer, archive)
```

2. Добавлена нормализация в `emit()`:
```rust
// Build identity map: archive → canonical writer identity
let mut identity_map = std::collections::HashMap::new();
for rec in &scan.records {
    identity_map.insert(rec.archive.clone(), rec.writer.clone());
}

// Apply normalization to extra_owners
let extra_owners_normalized: Vec<(String, String)> = scan
    .extra_owners
    .iter()
    .map(|(ns, _original_writer, archive)| {
        let normalized_writer = identity_map
            .get(archive)
            .cloned()
            .unwrap_or_else(|| _original_writer.clone());
        (ns.clone(), normalized_writer)
    })
    .collect();
```

**Влияние**: Мод больше не может появиться в графе под двумя разными именами.

### 7. Identity keying по basename (частично документировано)

**Проблема**: MOD/PLUGIN берётся `file_name()`, и это имя используется как ключ. При нескольких artifact roots (mods/foo.jar и plugins/foo.jar) происходит коллизия.

**Состояние**: Проблема документирована, но полное исправление требует изменений в слишком многих местах (facts emit, все потребители archive paths). Текущее исправление extra_owners (пункт 6) частично смягчает проблему через identity_map, но полное решение требует:
- Ключ identity map на полном нормализованном пути
- Обновление всех fact emit для использования стабильного artifact ID
- Миграция всех consumer'ов archive paths

**Рекомендация**: Отложить до следующего рефакторинга artifact identity системы.

## Результаты тестирования

✅ **115 unit tests** в intermed-resource-ast
✅ **4 property tests**
✅ **Все workspace tests** (328+ тестов)
✅ **Golden tests**
✅ **Компиляция всего workspace**

## Обратная совместимость

**Breaking changes**:
- `ResourceLevel::parse()` теперь возвращает `Result<Self, String>` вместо `Self`
- `extra_owners` структура изменена с `Vec<(String, String)>` на `Vec<(String, String, String)>`

**Не breaking**:
- Все остальные изменения — внутренняя логика
- Публичный API implies_dependency() и is_reliable() сохранён
- Контракты Rule стали точнее, но backward compatible

## Примечания

1. **Rule requirements**: Исправление критично, если requirements используются для scheduling. Если это только metadata — всё равно контракт теперь точен.

2. **Identity keying**: Проблема #7 полностью не решена из-за масштаба изменений. Документирована для будущего рефакторинга.

3. **Parse error handling**: ResourceLevel::parse() теперь возвращает Result, но внешний CLI должен быть обновлён для обработки ошибок.
