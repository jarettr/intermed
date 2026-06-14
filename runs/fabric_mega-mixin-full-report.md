# InterMed — отчёт по совместимости модов

**Пак:** `fabric_mega`  
**Путь:** `/home/mak/intermed_corpus/fabric_mega`  
**Дата:** 2026-06-14T10:48:30.690642414Z  
**Версия InterMed:** 0.1.0

## Окружение

ОС: linux · Java: 25.0.3 · Сторона: both · Тип: integrated · Layout: bare-mods-dir

## Сводка

| Показатель | Значение |
|------------|----------|
| Вердикт | **ЕСТЬ ОШИБКИ** |
| Всего findings | 4910 |
| Fatal | 0 |
| Error | 25 |
| Warn | 1580 |
| Note | 3305 |
| Info | 0 |

### По категориям

| Категория | Кол-во |
|-----------|--------|
| mixin | 4449 |
| resource | 216 |
| security | 142 |
| performance | 77 |
| dependency | 26 |

### Топ правил (по числу срабатываний)

| Правило | Кол-во |
|--------|--------|
| `mixin-risk` | 4449 |
| `resource-conflict` | 216 |
| `performance` | 66 |
| `sbom-provenance` | 62 |
| `unsigned-jar` | 62 |
| `dependency` | 26 |
| `security-api-risk` | 18 |
| `performance-correlation` | 11 |

## Критические проблемы (Error / Fatal)

### 1. [ERROR] Missing dependency: balm-fabric

waystones requires balm-fabric (>=7.0.0), but it is not installed.

**Затронуто:** waystones

- **Рекомендация:** Install balm-fabric matching >=7.0.0.
*Правило: `dependency` · id: `missing-dependency:waystones->balm-fabric`*

### 2. [ERROR] Missing dependency: badpackets

wthit requires badpackets (>=0.4.1), but it is not installed.

**Затронуто:** wthit

- **Рекомендация:** Install badpackets matching >=0.4.1.
*Правило: `dependency` · id: `missing-dependency:wthit->badpackets`*

### 3. [ERROR] Hot mod `iris` (11.0% CPU) modifies 118 class(es) via mixin

Spark attributes 11.0% CPU to mod `iris`, which modifies 118 class(es) via mixin. It @Overwrites 5: me.jellysquid.mods.sodium.client.gl.attribute.GlVertexFormat$Builder, me.jellysquid.mods.sodium.client.render.immediate.model.BakedModelEncoder, net.minecraft.class_382, net.minecraft.class_4970$class_4971, net.minecraft.class_630.

**Затронуто:** iris

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:iris`*

### 4. [ERROR] Hot mod `lithium` (14.5% CPU) modifies 123 class(es) via mixin

Spark attributes 14.5% CPU to mod `lithium`, which modifies 123 class(es) via mixin. It @Overwrites 40: net.minecraft.block.ComposterBlock$ComposterInventory, net.minecraft.block.ComposterBlock$DummyInventory, net.minecraft.block.ComposterBlock$FullComposterInventory, net.minecraft.class_1297, net.minecraft.class_1937, net.minecraft.class_1946, net.minecraft.class_1950, net.minecraft.class_1959, net.minecraft.class_2248, net.minecraft.class_2248$class_2249, net.minecraft.class_2338, net.minecraft.class_2350, net.minecraft.class_238, net.minecraft.class_246, net.minecraft.class_2487, net.minecraft.class_249, net.minecraft.class_259, net.minecraft.class_2614, net.minecraft.class_265, net.minecraft.class_2818, net.minecraft.class_2841, net.minecraft.class_2945, net.minecraft.class_3215, net.minecraft.class_3233, net.minecraft.class_3509, net.minecraft.class_3532, net.minecraft.class_3610, net.minecraft.class_3754, net.minecraft.class_3765, net.minecraft.class_3898, net.minecraft.class_4095, net.minecraft.class_4097, net.minecraft.class_4103, net.minecraft.class_4153, net.minecraft.class_5361, net.minecraft.class_5574, net.minecraft.class_6012, net.minecraft.class_6755, net.minecraft.util.math.AxisCycleDirection$2, net.minecraft.util.math.AxisCycleDirection$3.

**Затронуто:** lithium

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:lithium`*

### 5. [ERROR] Hot mod `modernfix` (6.5% CPU) modifies 97 class(es) via mixin

Spark attributes 6.5% CPU to mod `modernfix`, which modifies 97 class(es) via mixin. It @Overwrites 16: net.minecraft.class_1959, net.minecraft.class_2370, net.minecraft.class_2769, net.minecraft.class_2791, net.minecraft.class_310, net.minecraft.class_3193, net.minecraft.class_3485, net.minecraft.class_4590, net.minecraft.class_6568, net.minecraft.class_6582, net.minecraft.class_6686$class_6709, net.minecraft.class_763, net.minecraft.class_773, net.minecraft.class_7853, net.minecraft.class_807, net.minecraft.world.level.levelgen.SurfaceRules$Context.

**Затронуто:** modernfix

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:modernfix`*

### 6. [ERROR] Hot mod `sodium` (22.0% CPU) modifies 59 class(es) via mixin

Spark attributes 22.0% CPU to mod `sodium`, which modifies 59 class(es) via mixin. It @Overwrites 13: net.minecraft.class_1095, net.minecraft.class_1097, net.minecraft.class_1959, net.minecraft.class_2350, net.minecraft.class_287, net.minecraft.class_3928, net.minecraft.class_4587, net.minecraft.class_4588, net.minecraft.class_4725, net.minecraft.class_630, net.minecraft.class_761, net.minecraft.class_7764$class_4728, net.minecraft.class_8251.

**Затронуто:** sodium

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:sodium`*

### 7. [ERROR] Hot method `net.minecraft.class_761.method_3257` is modified by 42 mixin(s)

Spark attributes 9.5% CPU to `net.minecraft.class_761.method_3257`, and Layer-F mixin intelligence shows mod(s) ad_astra, ae2, botania, carryon, create, entityculling, iris, patchouli, player-animator, railways, resourcefullib, sodium, sodium-extra, supermartijn642corelib, supplementaries modifying this class via accessor, inject, invoker, modify-arg, modify-expression-value, modify-variable, overwrite, redirect, shadow, unique, unknown, wrap-operation, wrap-with-condition. At least one mixin @Overwrite replaces the original method wholesale — the most likely cause of the regression and the first thing to audit. Multiple mods target the same hot class, so their mixins also risk interacting.

**Затронуто:** net.minecraft.class_761, ad_astra, ae2, botania, carryon, create, entityculling, iris, patchouli, player-animator, railways, resourcefullib, sodium, sodium-extra, supermartijn642corelib, supplementaries

- **Рекомендация:** Audit the @Overwrite mixin(s) on this class; prefer @Inject/@Redirect, or disable the offending mod and re-profile.
*Правило: `performance-correlation` · id: `perf-mixin:net.minecraft.class_761:method_3257`*

### 8. [ERROR] Hot method `net.minecraft.server.MinecraftServer.tick` is modified by 13 mixin(s)

Spark attributes 12.0% CPU to `net.minecraft.server.MinecraftServer.tick`, and Layer-F mixin intelligence shows mod(s) ae2, modernfix, moonlight, xaerominimap, xaeroworldmap modifying this class via inject, modify-arg, redirect, unknown, wrap-operation. Multiple mods target the same hot class, so their mixins also risk interacting.

**Затронуто:** net.minecraft.server.MinecraftServer, ae2, modernfix, moonlight, xaerominimap, xaeroworldmap

- **Рекомендация:** Review the mixins targeting this class and re-profile with each disabled to isolate the cost.
*Правило: `performance-correlation` · id: `perf-mixin:net.minecraft.server.MinecraftServer:tick`*

### Mixin apply-failure: 17 подтверждённых ошибок

### 9. [ERROR] Mixin will not apply: `appeng.mixins.unlitquad.BlockModelMixin` -> net.minecraft.class_793

`ae2` (appeng.mixins.unlitquad.BlockModelMixin): method `bakeFace` not found on `net.minecraft.class_793` and require>=1 — the mixin fails to apply.

**Затронуто:** ae2

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_require_unsatisfied:ae2:net.minecraft.class_793:bakeFace`*

### 10. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.ai.useless_sensors.parent_animal_sensor.PassiveEntityMixin` -> net.minecraft.class_1296

`lithium` (me.jellysquid.mods.lithium.mixin.ai.useless_sensors.parent_animal_sensor.PassiveEntityMixin): method `onTrackedDataSet` not found on `net.minecraft.class_1296` and require>=1 — the mixin fails to apply.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_require_unsatisfied:lithium:net.minecraft.class_1296:onTrackedDataSet`*

### 11. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.entity.collisions.movement.EntityMixin` -> net.minecraft.class_1297

`lithium` (me.jellysquid.mods.lithium.mixin.entity.collisions.movement.EntityMixin): method `adjustMovementForCollisions` not found on `net.minecraft.class_1297` and require>=1 — the mixin fails to apply.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_require_unsatisfied:lithium:net.minecraft.class_1297:adjustMovementForCollisions(Lnet/minecraft/util/math/Vec3d;)Lnet/minecraft/util/math/Vec3d;`*

### 12. [ERROR] Mixin will not apply: `net.mehvahdjukaar.moonlight.core.mixins.PistonBlockEntityMixin` -> net.minecraft.class_2669

`moonlight` (net.mehvahdjukaar.moonlight.core.mixins.PistonBlockEntityMixin): method `tick` not found on `net.minecraft.class_2669` and require>=1 — the mixin fails to apply.

**Затронуто:** moonlight

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_require_unsatisfied:moonlight:net.minecraft.class_2669:tick`*

### 13. [ERROR] Mixin will not apply: `net.mehvahdjukaar.moonlight.core.mixins.ItemInHandRendererMixin` -> net.minecraft.class_759

`moonlight` (net.mehvahdjukaar.moonlight.core.mixins.ItemInHandRendererMixin): method `renderArmWithItem` not found on `net.minecraft.class_759` and require>=1 — the mixin fails to apply.

**Затронуто:** moonlight

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_require_unsatisfied:moonlight:net.minecraft.class_759:renderArmWithItem`*

### 14. [ERROR] Mixin will not apply: `net.mehvahdjukaar.supplementaries.mixins.MapItemMixin` -> net.minecraft.class_1806

`supplementaries` (net.mehvahdjukaar.supplementaries.mixins.MapItemMixin): method `update` not found on `net.minecraft.class_1806` and require>=1 — the mixin fails to apply.

**Затронуто:** supplementaries

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_require_unsatisfied:supplementaries:net.minecraft.class_1806:update`*

### 15. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.alloc.composter.ComposterMixin$ComposterBlockComposterInventoryMixin` -> net.minecraft.block.ComposterBlock$ComposterInventory

`lithium` (me.jellysquid.mods.lithium.mixin.alloc.composter.ComposterMixin$ComposterBlockComposterInventoryMixin): target class `net.minecraft.block.ComposterBlock$ComposterInventory` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.block.ComposterBlock$ComposterInventory:`*

### 16. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.alloc.composter.ComposterMixin$ComposterBlockDummyInventoryMixin` -> net.minecraft.block.ComposterBlock$DummyInventory

`lithium` (me.jellysquid.mods.lithium.mixin.alloc.composter.ComposterMixin$ComposterBlockDummyInventoryMixin): target class `net.minecraft.block.ComposterBlock$DummyInventory` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.block.ComposterBlock$DummyInventory:`*

### 17. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.alloc.composter.ComposterMixin$ComposterBlockFullComposterInventoryMixin` -> net.minecraft.block.ComposterBlock$FullComposterInventory

`lithium` (me.jellysquid.mods.lithium.mixin.alloc.composter.ComposterMixin$ComposterBlockFullComposterInventoryMixin): target class `net.minecraft.block.ComposterBlock$FullComposterInventory` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.block.ComposterBlock$FullComposterInventory:`*

### 18. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.entity.inactive_navigations.DrownedEntityLeaveWaterGoalMixin` -> net.minecraft.entity.mob.DrownedEntity$LeaveWaterGoal

`lithium` (me.jellysquid.mods.lithium.mixin.entity.inactive_navigations.DrownedEntityLeaveWaterGoalMixin): target class `net.minecraft.entity.mob.DrownedEntity$LeaveWaterGoal` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.entity.mob.DrownedEntity$LeaveWaterGoal:`*

### 19. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.ai.poi.tasks.RaiderEntityAttackHomeGoalMixin` -> net.minecraft.entity.raid.RaiderEntity$AttackHomeGoal

`lithium` (me.jellysquid.mods.lithium.mixin.ai.poi.tasks.RaiderEntityAttackHomeGoalMixin): target class `net.minecraft.entity.raid.RaiderEntity$AttackHomeGoal` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.entity.raid.RaiderEntity$AttackHomeGoal:`*

### 20. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.alloc.nbt.NbtCompoundMixin$Type` -> net.minecraft.nbt.NbtCompound$1

`lithium` (me.jellysquid.mods.lithium.mixin.alloc.nbt.NbtCompoundMixin$Type): target class `net.minecraft.nbt.NbtCompound$1` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.nbt.NbtCompound$1:`*

### 21. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.ai.nearby_entity_tracking.ServerEntityManagerListenerMixin` -> net.minecraft.server.world.ServerEntityManager$Listener

`lithium` (me.jellysquid.mods.lithium.mixin.ai.nearby_entity_tracking.ServerEntityManagerListenerMixin): target class `net.minecraft.server.world.ServerEntityManager$Listener` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.server.world.ServerEntityManager$Listener:`*

### 22. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.math.fast_util.AxisCycleDirectionMixin$ForwardMixin` -> net.minecraft.util.math.AxisCycleDirection$2

`lithium` (me.jellysquid.mods.lithium.mixin.math.fast_util.AxisCycleDirectionMixin$ForwardMixin): target class `net.minecraft.util.math.AxisCycleDirection$2` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.util.math.AxisCycleDirection$2:`*

### 23. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.math.fast_util.AxisCycleDirectionMixin$BackwardMixin` -> net.minecraft.util.math.AxisCycleDirection$3

`lithium` (me.jellysquid.mods.lithium.mixin.math.fast_util.AxisCycleDirectionMixin$BackwardMixin): target class `net.minecraft.util.math.AxisCycleDirection$3` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.util.math.AxisCycleDirection$3:`*

### 24. [ERROR] Mixin will not apply: `me.jellysquid.mods.lithium.mixin.world.block_entity_ticking.support_cache.DirectBlockEntityTickInvokerMixin` -> net.minecraft.world.chunk.WorldChunk$DirectBlockEntityTickInvoker

`lithium` (me.jellysquid.mods.lithium.mixin.world.block_entity_ticking.support_cache.DirectBlockEntityTickInvokerMixin): target class `net.minecraft.world.chunk.WorldChunk$DirectBlockEntityTickInvoker` not found in the Minecraft jar.

**Затронуто:** lithium

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:lithium:net.minecraft.world.chunk.WorldChunk$DirectBlockEntityTickInvoker:`*

### 25. [ERROR] Mixin will not apply: `org.embeddedt.modernfix.fabric.mixin.perf.faster_command_suggestions.SuggestionsBuilderMixin` -> com.mojang.brigadier.suggestion.SuggestionsBuilder

`modernfix` (org.embeddedt.modernfix.fabric.mixin.perf.faster_command_suggestions.SuggestionsBuilderMixin): target class `com.mojang.brigadier.suggestion.SuggestionsBuilder` not found in the Minecraft jar.

**Затронуто:** modernfix

- **Рекомендация:** Verify the target class/method exists in the installed version; rebuild the mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar for full apply verification.
*Правило: `mixin-risk` · id: `mixin-apply:mixin_apply_target_class_missing:modernfix:com.mojang.brigadier.suggestion.SuggestionsBuilder:`*

## Spark / Performance (Layer I)

Всего performance-findings: **77**

### 1. [ERROR] Hot mod `iris` (11.0% CPU) modifies 118 class(es) via mixin

Spark attributes 11.0% CPU to mod `iris`, which modifies 118 class(es) via mixin. It @Overwrites 5: me.jellysquid.mods.sodium.client.gl.attribute.GlVertexFormat$Builder, me.jellysquid.mods.sodium.client.render.immediate.model.BakedModelEncoder, net.minecraft.class_382, net.minecraft.class_4970$class_4971, net.minecraft.class_630.

**Затронуто:** iris

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:iris`*

### 2. [ERROR] Hot mod `lithium` (14.5% CPU) modifies 123 class(es) via mixin

Spark attributes 14.5% CPU to mod `lithium`, which modifies 123 class(es) via mixin. It @Overwrites 40: net.minecraft.block.ComposterBlock$ComposterInventory, net.minecraft.block.ComposterBlock$DummyInventory, net.minecraft.block.ComposterBlock$FullComposterInventory, net.minecraft.class_1297, net.minecraft.class_1937, net.minecraft.class_1946, net.minecraft.class_1950, net.minecraft.class_1959, net.minecraft.class_2248, net.minecraft.class_2248$class_2249, net.minecraft.class_2338, net.minecraft.class_2350, net.minecraft.class_238, net.minecraft.class_246, net.minecraft.class_2487, net.minecraft.class_249, net.minecraft.class_259, net.minecraft.class_2614, net.minecraft.class_265, net.minecraft.class_2818, net.minecraft.class_2841, net.minecraft.class_2945, net.minecraft.class_3215, net.minecraft.class_3233, net.minecraft.class_3509, net.minecraft.class_3532, net.minecraft.class_3610, net.minecraft.class_3754, net.minecraft.class_3765, net.minecraft.class_3898, net.minecraft.class_4095, net.minecraft.class_4097, net.minecraft.class_4103, net.minecraft.class_4153, net.minecraft.class_5361, net.minecraft.class_5574, net.minecraft.class_6012, net.minecraft.class_6755, net.minecraft.util.math.AxisCycleDirection$2, net.minecraft.util.math.AxisCycleDirection$3.

**Затронуто:** lithium

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:lithium`*

### 3. [ERROR] Hot mod `modernfix` (6.5% CPU) modifies 97 class(es) via mixin

Spark attributes 6.5% CPU to mod `modernfix`, which modifies 97 class(es) via mixin. It @Overwrites 16: net.minecraft.class_1959, net.minecraft.class_2370, net.minecraft.class_2769, net.minecraft.class_2791, net.minecraft.class_310, net.minecraft.class_3193, net.minecraft.class_3485, net.minecraft.class_4590, net.minecraft.class_6568, net.minecraft.class_6582, net.minecraft.class_6686$class_6709, net.minecraft.class_763, net.minecraft.class_773, net.minecraft.class_7853, net.minecraft.class_807, net.minecraft.world.level.levelgen.SurfaceRules$Context.

**Затронуто:** modernfix

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:modernfix`*

### 4. [ERROR] Hot mod `sodium` (22.0% CPU) modifies 59 class(es) via mixin

Spark attributes 22.0% CPU to mod `sodium`, which modifies 59 class(es) via mixin. It @Overwrites 13: net.minecraft.class_1095, net.minecraft.class_1097, net.minecraft.class_1959, net.minecraft.class_2350, net.minecraft.class_287, net.minecraft.class_3928, net.minecraft.class_4587, net.minecraft.class_4588, net.minecraft.class_4725, net.minecraft.class_630, net.minecraft.class_761, net.minecraft.class_7764$class_4728, net.minecraft.class_8251.

**Затронуто:** sodium

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:sodium`*

### 5. [ERROR] Hot method `net.minecraft.class_761.method_3257` is modified by 42 mixin(s)

Spark attributes 9.5% CPU to `net.minecraft.class_761.method_3257`, and Layer-F mixin intelligence shows mod(s) ad_astra, ae2, botania, carryon, create, entityculling, iris, patchouli, player-animator, railways, resourcefullib, sodium, sodium-extra, supermartijn642corelib, supplementaries modifying this class via accessor, inject, invoker, modify-arg, modify-expression-value, modify-variable, overwrite, redirect, shadow, unique, unknown, wrap-operation, wrap-with-condition. At least one mixin @Overwrite replaces the original method wholesale — the most likely cause of the regression and the first thing to audit. Multiple mods target the same hot class, so their mixins also risk interacting.

**Затронуто:** net.minecraft.class_761, ad_astra, ae2, botania, carryon, create, entityculling, iris, patchouli, player-animator, railways, resourcefullib, sodium, sodium-extra, supermartijn642corelib, supplementaries

- **Рекомендация:** Audit the @Overwrite mixin(s) on this class; prefer @Inject/@Redirect, or disable the offending mod and re-profile.
*Правило: `performance-correlation` · id: `perf-mixin:net.minecraft.class_761:method_3257`*

### 6. [ERROR] Hot method `net.minecraft.server.MinecraftServer.tick` is modified by 13 mixin(s)

Spark attributes 12.0% CPU to `net.minecraft.server.MinecraftServer.tick`, and Layer-F mixin intelligence shows mod(s) ae2, modernfix, moonlight, xaerominimap, xaeroworldmap modifying this class via inject, modify-arg, redirect, unknown, wrap-operation. Multiple mods target the same hot class, so their mixins also risk interacting.

**Затронуто:** net.minecraft.server.MinecraftServer, ae2, modernfix, moonlight, xaerominimap, xaeroworldmap

- **Рекомендация:** Review the mixins targeting this class and re-profile with each disabled to isolate the cost.
*Правило: `performance-correlation` · id: `perf-mixin:net.minecraft.server.MinecraftServer:tick`*

### 7. [WARN] Hot mod `create` (5.8% CPU) also collides on 74 resource path(s)

Spark attributes 5.8% CPU to `create` and it is among the writers for conflicting resource path(s): assets/minecraft/atlases/blocks.json, data/c/tags/blocks/brass_blocks.json, data/c/tags/blocks/glass_panes.json, data/c/tags/blocks/ores.json, data/c/tags/blocks/relocation_not_supported.json, data/c/tags/blocks/storage_blocks.json, data/c/tags/blocks/zinc_blocks.json, data/c/tags/items/brass_blocks.json, data/c/tags/items/brass_ingots.json, data/c/tags/items/brass_nuggets.json, data/c/tags/items/brass_plates.json, data/c/tags/items/copper_nuggets.json, data/c/tags/items/copper_plates.json, data/c/tags/items/dough.json, data/c/tags/items/glass_panes.json, data/c/tags/items/gold_plates.json, data/c/tags/items/ingots.json, data/c/tags/items/iron_plates.json, data/c/tags/items/nuggets.json, data/c/tags/items/obsidian_dusts.json, data/c/tags/items/obsidian_plates.json, data/c/tags/items/ores.json, data/c/tags/items/plates.json, data/c/tags/items/raw_zinc_ores.json, data/c/tags/items/storage_blocks.json, data/c/tags/items/wrenches.json, data/c/tags/items/zinc_blocks.json, data/c/tags/items/zinc_ingots.json, data/c/tags/items/zinc_nuggets.json, data/create/recipes/crushing/ochrum.json, data/create/recipes/crushing/ochrum_recycling.json, data/create/recipes/crushing/tuff.json, data/create/recipes/crushing/tuff_recycling.json, data/create/tags/blocks/copycat_deny.json, data/create/tags/blocks/fan_processing_catalysts/blasting.json, data/create/tags/blocks/fan_transparent.json, data/create/tags/blocks/girdable_tracks.json, data/create/tags/blocks/movable_empty_collider.json, data/create/tags/blocks/passive_boiler_heaters.json, data/create/tags/blocks/safe_nbt.json, data/create/tags/blocks/tracks.json, data/create/tags/blocks/wrench_pickup.json, data/create/tags/items/contraption_controlled.json, data/create/tags/items/sandpaper.json, data/create/tags/items/tracks.json, data/create/tags/items/upright_on_belt.json, data/minecraft/tags/blocks/beacon_base_blocks.json, data/minecraft/tags/blocks/climbable.json, data/minecraft/tags/blocks/combination_step_sound_blocks.json, data/minecraft/tags/blocks/doors.json, data/minecraft/tags/blocks/impermeable.json, data/minecraft/tags/blocks/inside_step_sound_blocks.json, data/minecraft/tags/blocks/mineable/axe.json, data/minecraft/tags/blocks/mineable/pickaxe.json, data/minecraft/tags/blocks/needs_iron_tool.json, data/minecraft/tags/blocks/needs_stone_tool.json, data/minecraft/tags/blocks/rails.json, data/minecraft/tags/blocks/slabs.json, data/minecraft/tags/blocks/stairs.json, data/minecraft/tags/blocks/trapdoors.json, data/minecraft/tags/blocks/walls.json, data/minecraft/tags/blocks/wooden_doors.json, data/minecraft/tags/damage_type/bypasses_armor.json, data/minecraft/tags/damage_type/is_explosion.json, data/minecraft/tags/fluids/water.json, data/minecraft/tags/items/beacon_payment_items.json, data/minecraft/tags/items/doors.json, data/minecraft/tags/items/piglin_loved.json, data/minecraft/tags/items/slabs.json, data/minecraft/tags/items/stairs.json, data/minecraft/tags/items/trapdoors.json, data/minecraft/tags/items/walls.json, data/quark/tags/blocks/non_double_door.json, data/trinkets/tags/items/head/face.json. Heavy tick cost plus pack resource contention often points at the same mod — try disabling it and re-profiling.

**Затронуто:** create

- **Рекомендация:** Resolve the resource collision or temporarily remove this mod, then re-profile.
*Правило: `performance` · id: `perf-hot-mod-resource:create`*

### 8. [WARN] Hot mod `modernfix` (6.5% CPU) also collides on 1 resource path(s)

Spark attributes 6.5% CPU to `modernfix` and it is among the writers for conflicting resource path(s): pack.mcmeta. Heavy tick cost plus pack resource contention often points at the same mod — try disabling it and re-profiling.

**Затронуто:** modernfix

- **Рекомендация:** Resolve the resource collision or temporarily remove this mod, then re-profile.
*Правило: `performance` · id: `perf-hot-mod-resource:modernfix`*

### 9. [WARN] Hot mod `create` (5.8% CPU) modifies 67 class(es) via mixin

Spark attributes 5.8% CPU to mod `create`, which modifies 67 class(es) via mixin.

**Затронуто:** create

- **Рекомендация:** Temporarily remove or disable this mod and re-profile to confirm its tick cost; review its mixin targets for redundant or hot-path patches.
*Правило: `performance-correlation` · id: `perf-hot-mod:create`*

### 10. [WARN] Hot method `me.jellysquid.mods.sodium.client.render.chunk.RenderSectionManager.update` is modified by 3 mixin(s)

Spark attributes 7.2% CPU to `me.jellysquid.mods.sodium.client.render.chunk.RenderSectionManager.update`, and Layer-F mixin intelligence shows mod(s) iris modifying this class via inject, modify-arg, redirect.

**Затронуто:** me.jellysquid.mods.sodium.client.render.chunk.RenderSectionManager, iris

- **Рекомендация:** Review the mixins targeting this class and re-profile with each disabled to isolate the cost.
*Правило: `performance-correlation` · id: `perf-mixin:me.jellysquid.mods.sodium.client.render.chunk.RenderSectionManager:update`*

### 11. [WARN] Tick spikes recorded while `ad_astra` patches 20 hot-path mixin target(s)

Spark reported server tick spikes (up to 120 ms) and mod `ad_astra` modifies hot-path class(es): net.minecraft.class_1007, net.minecraft.class_1297, net.minecraft.class_1309, net.minecraft.class_1536, net.minecraft.class_1541, net.minecraft.class_1542, net.minecraft.class_1657, net.minecraft.class_1665, net.minecraft.class_1682, net.minecraft.class_1688, net.minecraft.class_1690, net.minecraft.class_1937, net.minecraft.class_3218, net.minecraft.class_3222, net.minecraft.class_3244, net.minecraft.class_3898, net.minecraft.class_465, net.minecraft.class_761, net.minecraft.class_898, net.minecraft.server.level.ServerLevel$EntityCallbacks. Mixin work on tick-critical targets is a prime lag suspect — profile with Spark and review these targets first.

**Затронуто:** ad_astra

- **Рекомендация:** Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.
*Правило: `performance` · id: `perf-tick-mixin-hotpath:ad_astra`*

### 12. [WARN] Tick spikes recorded while `ae2` patches 10 hot-path mixin target(s)

Spark reported server tick spikes (up to 120 ms) and mod `ae2` modifies hot-path class(es): net.minecraft.class_1309, net.minecraft.class_1542, net.minecraft.class_1657, net.minecraft.class_1937, net.minecraft.class_310, net.minecraft.class_3218, net.minecraft.class_3898, net.minecraft.class_465, net.minecraft.class_761, net.minecraft.server.MinecraftServer. Mixin work on tick-critical targets is a prime lag suspect — profile with Spark and review these targets first.

**Затронуто:** ae2

- **Рекомендация:** Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.
*Правило: `performance` · id: `perf-tick-mixin-hotpath:ae2`*

### 13. [WARN] Tick spikes recorded while `appleskin` patches 4 hot-path mixin target(s)

Spark reported server tick spikes (up to 120 ms) and mod `appleskin` modifies hot-path class(es): net.minecraft.class_310, net.minecraft.class_3222, net.minecraft.class_329, net.minecraft.class_340. Mixin work on tick-critical targets is a prime lag suspect — profile with Spark and review these targets first.

**Затронуто:** appleskin

- **Рекомендация:** Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.
*Правило: `performance` · id: `perf-tick-mixin-hotpath:appleskin`*

### 14. [WARN] Tick spikes recorded while `architectury` patches 20 hot-path mixin target(s)

Spark reported server tick spikes (up to 120 ms) and mod `architectury` modifies hot-path class(es): net.minecraft.class_1297, net.minecraft.class_1309, net.minecraft.class_1387, net.minecraft.class_1538, net.minecraft.class_1540, net.minecraft.class_1542, net.minecraft.class_1657, net.minecraft.class_1661, net.minecraft.class_1937, net.minecraft.class_1959, net.minecraft.class_2248, net.minecraft.class_2910, net.minecraft.class_310, net.minecraft.class_3218, net.minecraft.class_3222, net.minecraft.class_340, net.minecraft.class_3898, net.minecraft.class_465, net.minecraft.class_746, net.minecraft.class_757. Mixin work on tick-critical targets is a prime lag suspect — profile with Spark and review these targets first.

**Затронуто:** architectury

- **Рекомендация:** Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.
*Правило: `performance` · id: `perf-tick-mixin-hotpath:architectury`*

### 15. [WARN] Tick spikes recorded while `botania` patches 21 hot-path mixin target(s)

Spark reported server tick spikes (up to 120 ms) and mod `botania` modifies hot-path class(es): net.minecraft.class_1297, net.minecraft.class_1309, net.minecraft.class_1542, net.minecraft.class_1657, net.minecraft.class_1661, net.minecraft.class_1682, net.minecraft.class_1688, net.minecraft.class_1937, net.minecraft.class_1959, net.minecraft.class_2358, net.minecraft.class_2580, net.minecraft.class_2609, net.minecraft.class_2614, net.minecraft.class_310, net.minecraft.class_3218, net.minecraft.class_3222, net.minecraft.class_337, net.minecraft.class_340, net.minecraft.class_465, net.minecraft.class_761, net.minecraft.class_918. Mixin work on tick-critical targets is a prime lag suspect — profile with Spark and review these targets first.

**Затронуто:** botania

- **Рекомендация:** Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.
*Правило: `performance` · id: `perf-tick-mixin-hotpath:botania`*

## Предупреждения (Warn)

*Показаны 30 из 1580 предупреждений (без performance, см. выше).*

### 1. [WARN] Mixin handler `com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi#polymorph$client`

unconditionally sets return value

**Затронуто:** polymorph

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi:polymorph$client`*

### 2. [WARN] Mixin handler `com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi#polymorph$common`

unconditionally sets return value

**Затронуто:** polymorph

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi:polymorph$common`*

### 3. [WARN] Mixin handler `com.railwayteam.railways.mixin.MixinTrain#frontCouplerListener`

unconditionally sets return value

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.MixinTrain:frontCouplerListener`*

### 4. [WARN] Mixin handler `com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer#shutUpSizeLimitFrom`

unconditionally sets return value

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer:shutUpSizeLimitFrom`*

### 5. [WARN] Mixin handler `com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer#shutUpSizeLimitTo`

unconditionally sets return value

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer:shutUpSizeLimitTo`*

### 6. [WARN] Mixin handler `com.railwayteam.railways.mixin.compat.malilib.MixinGuiTextFieldGeneric#fixCursorPosition`

unconditionally cancels via CallbackInfo

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.compat.malilib.MixinGuiTextFieldGeneric:fixCursorPosition`*

### 7. [WARN] Mixin handler `earth.terrarium.adastra.mixins.client.HumanoidModelMixin#adastra$setupAnim`

writes target state

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.client.HumanoidModelMixin:adastra$setupAnim`*

### 8. [WARN] Mixin handler `earth.terrarium.adastra.mixins.common.gravity.ThrowableProjectileMixin#adastra$getGravity`

unconditionally sets return value

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.common.gravity.ThrowableProjectileMixin:adastra$getGravity`*

### 9. [WARN] Mixin handler `earth.terrarium.adastra.mixins.common.gravity.ThrownExperienceBottleMixin#adastra$getGravity`

unconditionally sets return value

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.common.gravity.ThrownExperienceBottleMixin:adastra$getGravity`*

### 10. [WARN] Mixin handler `earth.terrarium.adastra.mixins.common.gravity.ThrownPotionMixin#adastra$getGravity`

unconditionally sets return value

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.common.gravity.ThrownPotionMixin:adastra$getGravity`*

### 11. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetCenterX`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetCenterX`*

### 12. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetCenterY`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetCenterY`*

### 13. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetLimitX`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetLimitX`*

### 14. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetLimitY`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetLimitY`*

### 15. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinSliderControlElement#rso$setValueFromMouse`

unconditionally cancels via CallbackInfo

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinSliderControlElement:rso$setValueFromMouse`*

### 16. [WARN] Mixin handler `me.flashyreese.mods.sodiumextra.mixin.optimizations.beacon_beam_rendering.MixinBeaconBlockEntityRenderer#optimizeRenderBeam`

unconditionally cancels via CallbackInfo; complexity 91/100

**Затронуто:** sodium-extra

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.sodiumextra.mixin.optimizations.beacon_beam_rendering.MixinBeaconBlockEntityRenderer:optimizeRenderBeam`*

### 17. [WARN] Mixin handler `me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI#rebuildGUIOptions`

unconditionally cancels via CallbackInfo

**Затронуто:** sodium-extra

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI:rebuildGUIOptions`*

### 18. [WARN] Mixin handler `me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI#renderOptionTooltip`

unconditionally cancels via CallbackInfo

**Затронуто:** sodium-extra

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI:renderOptionTooltip`*

### 19. [WARN] Mixin handler `me.jellysquid.mods.lithium.mixin.block.redstone_wire.RedstoneWireBlockMixin#getReceivedPowerFaster`

unconditionally sets return value

**Затронуто:** lithium

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.jellysquid.mods.lithium.mixin.block.redstone_wire.RedstoneWireBlockMixin:getReceivedPowerFaster`*

### 20. [WARN] Mixin handler `me.jellysquid.mods.lithium.mixin.shapes.shape_merging.VoxelShapesMixin#injectCustomListPair`

unconditionally sets return value

**Затронуто:** lithium

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.jellysquid.mods.lithium.mixin.shapes.shape_merging.VoxelShapesMixin:injectCustomListPair`*

### 21. [WARN] Mixin handler `me.jellysquid.mods.sodium.mixin.features.gui.hooks.settings.OptionsScreenMixin#open`

unconditionally sets return value

**Затронуто:** sodium

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.jellysquid.mods.sodium.mixin.features.gui.hooks.settings.OptionsScreenMixin:open`*

### 22. [WARN] Mixin handler `net.irisshaders.iris.mixin.MixinProgram#iris$causeException`

unconditionally cancels via CallbackInfo

**Затронуто:** iris

*Правило: `mixin-risk` · id: `mixin-handler-intel:net.irisshaders.iris.mixin.MixinProgram:iris$causeException`*

### 23. [WARN] Mixin handler `org.embeddedt.modernfix.common.mixin.feature.remove_chat_signing.ChatTrustLevelMixin#alwaysShowSecure`

unconditionally sets return value

**Затронуто:** modernfix

*Правило: `mixin-risk` · id: `mixin-handler-intel:org.embeddedt.modernfix.common.mixin.feature.remove_chat_signing.ChatTrustLevelMixin:alwaysShowSecure`*

### 24. [WARN] Mixin handler `org.embeddedt.modernfix.common.mixin.feature.remove_telemetry.ClientTelemetryManagerMixin#disableTelemetrySender`

unconditionally sets return value

**Затронуто:** modernfix

*Правило: `mixin-risk` · id: `mixin-handler-intel:org.embeddedt.modernfix.common.mixin.feature.remove_telemetry.ClientTelemetryManagerMixin:disableTelemetrySender`*

### 25. [WARN] Mixin handler `org.embeddedt.modernfix.common.mixin.feature.remove_telemetry.MinecraftMixin_Telemetry#markTelemetryNotAllowed`

unconditionally sets return value

**Затронуто:** modernfix

*Правило: `mixin-risk` · id: `mixin-handler-intel:org.embeddedt.modernfix.common.mixin.feature.remove_telemetry.MinecraftMixin_Telemetry:markTelemetryNotAllowed`*

### 26. [WARN] Mixin handler `org.embeddedt.modernfix.common.mixin.perf.cache_strongholds.ChunkGeneratorMixin#saveCachedData`

unconditionally sets return value

**Затронуто:** modernfix

*Правило: `mixin-risk` · id: `mixin-handler-intel:org.embeddedt.modernfix.common.mixin.perf.cache_strongholds.ChunkGeneratorMixin:saveCachedData`*

### 27. [WARN] Mixin handler `org.embeddedt.modernfix.common.mixin.perf.dynamic_entity_renderers.EntityRenderersMixin#createDynamicRendererLoader`

unconditionally sets return value

**Затронуто:** modernfix

*Правило: `mixin-risk` · id: `mixin-handler-intel:org.embeddedt.modernfix.common.mixin.perf.dynamic_entity_renderers.EntityRenderersMixin:createDynamicRendererLoader`*

### 28. [WARN] Mixin interaction on me.jellysquid.mods.sodium.client.render.vertex.serializers.VertexSerializerRegistryImpl

Both inject into site `<init>@TAIL` on `me.jellysquid.mods.sodium.client.render.vertex.serializers.VertexSerializerRegistryImpl`

**Затронуто:** me.jellysquid.mods.sodium.client.render.vertex.serializers.VertexSerializerRegistryImpl

- **Рекомендация:** Review mod load order, mixin priority, and compatibility notes for these mods.
*Правило: `mixin-risk` · id: `mixin-interaction:interaction-1`*

### 29. [WARN] Mixin interaction on net.minecraft.class_1041

Both inject into site `<init>(Lnet/minecraft/class_3678;Lnet/minecraft/class_323;Lnet/minecraft/class_543;Ljava/lang/String;Ljava/lang/String;)V@INVOKE|Lorg.lwjgl.glfw.GLFW;glfwCreateWindow(IILjava.lang.CharSequence;JJ)J` on `net.minecraft.class_1041`

**Затронуто:** net.minecraft.class_1041

- **Рекомендация:** Review mod load order, mixin priority, and compatibility notes for these mods.
*Правило: `mixin-risk` · id: `mixin-interaction:interaction-2`*

### 30. [WARN] Mixin interaction on net.minecraft.class_1059

Both inject into site `upload@RETURN` on `net.minecraft.class_1059`

**Затронуто:** net.minecraft.class_1059

- **Рекомендация:** Review mod load order, mixin priority, and compatibility notes for these mods.
*Правило: `mixin-risk` · id: `mixin-interaction:interaction-3`*

## Mixin-анализ (Layer F)

Всего mixin-findings: **4449** (error/warn: 1499, note: 2950)

### Наиболее значимые mixin-находки (handler effects + interactions)

### 1. [WARN] Mixin handler `com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi#polymorph$client`

unconditionally sets return value

**Затронуто:** polymorph

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi:polymorph$client`*

### 2. [WARN] Mixin handler `com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi#polymorph$common`

unconditionally sets return value

**Затронуто:** polymorph

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.illusivesoulworks.polymorph.mixin.core.MixinPolymorphApi:polymorph$common`*

### 3. [WARN] Mixin handler `com.railwayteam.railways.mixin.MixinTrain#frontCouplerListener`

unconditionally sets return value

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.MixinTrain:frontCouplerListener`*

### 4. [WARN] Mixin handler `com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer#shutUpSizeLimitFrom`

unconditionally sets return value

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer:shutUpSizeLimitFrom`*

### 5. [WARN] Mixin handler `com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer#shutUpSizeLimitTo`

unconditionally sets return value

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.client.MixinBlockElement_Deserializer:shutUpSizeLimitTo`*

### 6. [WARN] Mixin handler `com.railwayteam.railways.mixin.compat.malilib.MixinGuiTextFieldGeneric#fixCursorPosition`

unconditionally cancels via CallbackInfo

**Затронуто:** railways

*Правило: `mixin-risk` · id: `mixin-handler-intel:com.railwayteam.railways.mixin.compat.malilib.MixinGuiTextFieldGeneric:fixCursorPosition`*

### 7. [WARN] Mixin handler `earth.terrarium.adastra.mixins.client.HumanoidModelMixin#adastra$setupAnim`

writes target state

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.client.HumanoidModelMixin:adastra$setupAnim`*

### 8. [WARN] Mixin handler `earth.terrarium.adastra.mixins.common.gravity.ThrowableProjectileMixin#adastra$getGravity`

unconditionally sets return value

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.common.gravity.ThrowableProjectileMixin:adastra$getGravity`*

### 9. [WARN] Mixin handler `earth.terrarium.adastra.mixins.common.gravity.ThrownExperienceBottleMixin#adastra$getGravity`

unconditionally sets return value

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.common.gravity.ThrownExperienceBottleMixin:adastra$getGravity`*

### 10. [WARN] Mixin handler `earth.terrarium.adastra.mixins.common.gravity.ThrownPotionMixin#adastra$getGravity`

unconditionally sets return value

**Затронуто:** ad_astra

*Правило: `mixin-risk` · id: `mixin-handler-intel:earth.terrarium.adastra.mixins.common.gravity.ThrownPotionMixin:adastra$getGravity`*

### 11. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetCenterX`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetCenterX`*

### 12. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetCenterY`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetCenterY`*

### 13. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetLimitX`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetLimitX`*

### 14. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i#redirectGetLimitY`

unconditionally sets return value

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinDim2i:redirectGetLimitY`*

### 15. [WARN] Mixin handler `me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinSliderControlElement#rso$setValueFromMouse`

unconditionally cancels via CallbackInfo

**Затронуто:** reeses-sodium-options

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.reeses_sodium_options.mixin.sodium.MixinSliderControlElement:rso$setValueFromMouse`*

### 16. [WARN] Mixin handler `me.flashyreese.mods.sodiumextra.mixin.optimizations.beacon_beam_rendering.MixinBeaconBlockEntityRenderer#optimizeRenderBeam`

unconditionally cancels via CallbackInfo; complexity 91/100

**Затронуто:** sodium-extra

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.sodiumextra.mixin.optimizations.beacon_beam_rendering.MixinBeaconBlockEntityRenderer:optimizeRenderBeam`*

### 17. [WARN] Mixin handler `me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI#rebuildGUIOptions`

unconditionally cancels via CallbackInfo

**Затронуто:** sodium-extra

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI:rebuildGUIOptions`*

### 18. [WARN] Mixin handler `me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI#renderOptionTooltip`

unconditionally cancels via CallbackInfo

**Затронуто:** sodium-extra

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.flashyreese.mods.sodiumextra.mixin.sodium.scrollable_page.MixinSodiumOptionsGUI:renderOptionTooltip`*

### 19. [WARN] Mixin handler `me.jellysquid.mods.lithium.mixin.block.redstone_wire.RedstoneWireBlockMixin#getReceivedPowerFaster`

unconditionally sets return value

**Затронуто:** lithium

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.jellysquid.mods.lithium.mixin.block.redstone_wire.RedstoneWireBlockMixin:getReceivedPowerFaster`*

### 20. [WARN] Mixin handler `me.jellysquid.mods.lithium.mixin.shapes.shape_merging.VoxelShapesMixin#injectCustomListPair`

unconditionally sets return value

**Затронуто:** lithium

*Правило: `mixin-risk` · id: `mixin-handler-intel:me.jellysquid.mods.lithium.mixin.shapes.shape_merging.VoxelShapesMixin:injectCustomListPair`*

## Заметки — конфликты ресурсов (Note)

*Показаны 20 из 210 merge-safe resource-конфликтов.*

### 1. [NOTE] Resource can be merged safely: data/c/tags/blocks/brass_blocks.json

2 writer(s) touch this path: create, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/brass_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/brass_blocks.json`*

### 2. [NOTE] Resource can be merged safely: data/c/tags/blocks/bronze_blocks.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/bronze_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/bronze_blocks.json`*

### 3. [NOTE] Resource can be merged safely: data/c/tags/blocks/electrum_blocks.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/electrum_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/electrum_blocks.json`*

### 4. [NOTE] Resource can be merged safely: data/c/tags/blocks/glass_panes.json

2 writer(s) touch this path: botania, create. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/glass_panes.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/glass_panes.json`*

### 5. [NOTE] Resource can be merged safely: data/c/tags/blocks/lead_blocks.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/lead_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/lead_blocks.json`*

### 6. [NOTE] Resource can be merged safely: data/c/tags/blocks/lead_ores.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/lead_ores.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/lead_ores.json`*

### 7. [NOTE] Resource can be merged safely: data/c/tags/blocks/ores.json

4 writer(s) touch this path: botania, create, powah, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/ores.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/ores.json`*

### 8. [NOTE] Tag entries carry required flags: data/c/tags/blocks/relocation_not_supported.json

2 writer(s) touch this tag: create, railways. tag entries carry `required` flags; values can still union but the optional/required semantics should be reviewed

**Затронуто:** data/c/tags/blocks/relocation_not_supported.json

- **Рекомендация:** Review the optional/required entries; values still union but semantics can differ.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/relocation_not_supported.json`*

### 9. [NOTE] Resource can be merged safely: data/c/tags/blocks/silver_blocks.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/silver_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/silver_blocks.json`*

### 10. [NOTE] Resource can be merged safely: data/c/tags/blocks/silver_ores.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/silver_ores.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/silver_ores.json`*

### 11. [NOTE] Resource can be merged safely: data/c/tags/blocks/steel_blocks.json

2 writer(s) touch this path: ad_astra, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/steel_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/steel_blocks.json`*

### 12. [NOTE] Resource can be merged safely: data/c/tags/blocks/storage_blocks.json

2 writer(s) touch this path: ae2, create. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/storage_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/storage_blocks.json`*

### 13. [NOTE] Resource can be merged safely: data/c/tags/blocks/tin_blocks.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/tin_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/tin_blocks.json`*

### 14. [NOTE] Resource can be merged safely: data/c/tags/blocks/tin_ores.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/tin_ores.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/tin_ores.json`*

### 15. [NOTE] Resource can be merged safely: data/c/tags/blocks/tungsten_blocks.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/tungsten_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/tungsten_blocks.json`*

### 16. [NOTE] Resource can be merged safely: data/c/tags/blocks/tungsten_ores.json

2 writer(s) touch this path: indrev, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/tungsten_ores.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/tungsten_ores.json`*

### 17. [NOTE] Resource can be merged safely: data/c/tags/blocks/zinc_blocks.json

2 writer(s) touch this path: create, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/blocks/zinc_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/blocks/zinc_blocks.json`*

### 18. [NOTE] Resource can be merged safely: data/c/tags/items/brass_blocks.json

2 writer(s) touch this path: create, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/items/brass_blocks.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/items/brass_blocks.json`*

### 19. [NOTE] Resource can be merged safely: data/c/tags/items/brass_ingots.json

3 writer(s) touch this path: create, createaddition, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/items/brass_ingots.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/items/brass_ingots.json`*

### 20. [NOTE] Resource can be merged safely: data/c/tags/items/brass_nuggets.json

3 writer(s) touch this path: create, createaddition, techreborn. all writers append values without replace — a deterministic, order-independent set union

**Затронуто:** data/c/tags/items/brass_nuggets.json

- **Рекомендация:** Generate an overlay preview and inspect the merged tag values.
*Правило: `resource-conflict` · id: `resource-conflict:data/c/tags/items/brass_nuggets.json`*

*…и ещё 190 заметок*

---

*Сгенерировано из `fabric_mega-mixin-full-report.json`. Параметры: `--mixin-level=full`, `--metadata-level=full`, `--minecraft-jar` (intermediary 1.20.1), `--minecraft-mappings` (Yarn Tiny v2), `--performance`, `--spark-report fabric_mega/spark/fabric_mega-profile.json`.*