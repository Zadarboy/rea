import type { DecodedComponent } from "../domain/wasm/wasmComponent.js";
import type { ComponentSort } from "../domain/wasm/wasmComponentTypes.js";
import type {
  ComponentIndexSpaces,
  IndexOrigin,
} from "./WasmComponentIndexSpaces.js";

/** Bounds export-of-export chains, which validation would reject if cyclic. */
const MAX_EXPORT_HOPS = 64;

/** Follow export re-aliases back to the entry that defined the index. */
const definingEntry = (
  spaces: ComponentIndexSpaces,
  sort: ComponentSort,
  index: number,
): { readonly index: number; readonly origin: IndexOrigin } | undefined => {
  let current = index;
  for (let hop = 0; hop < MAX_EXPORT_HOPS; hop += 1) {
    const origin = spaces.origin(sort, current);
    if (origin === undefined) return undefined;
    if (origin.kind !== "export") return { index: current, origin };
    current = origin.of;
  }
  return undefined;
};

type CoreInterface = DecodedComponent["core_modules"][number]["interface"];

const moduleInterface = (
  component: DecodedComponent,
  module: number,
): CoreInterface | undefined =>
  component.core_modules.find((entry) => entry.index === module)?.interface;

const declaresExport = (
  component: DecodedComponent,
  module: number | null,
  name: string,
): boolean | null => {
  if (module === null) return null;
  const found = moduleInterface(component, module);
  if (found?.status !== "decoded") return null;
  return found.exports.some(
    (entry) => entry.kind === "func" && entry.name === name,
  );
};

const declaresImport = (
  component: DecodedComponent,
  module: number,
  importModule: string,
  importName: string,
): boolean | null => {
  const found = moduleInterface(component, module);
  if (found?.status !== "decoded") return null;
  return found.imports.some(
    (entry) =>
      entry.type.kind === "func" &&
      entry.module === importModule &&
      entry.name === importName,
  );
};

type CoreBinding = DecodedComponent["lowers"][number]["satisfies"][number];

/** Instantiations that receive `provider` as an argument, as bindings of `name`. */
const bindingsOf = (
  component: DecodedComponent,
  provider: number,
  name: string,
): CoreBinding[] =>
  component.core_instances.flatMap((consumer) => {
    const index = consumer.index;
    if (consumer.kind !== "instantiate" || index === null) return [];
    return consumer.args
      .filter((argument) => argument.instance === provider)
      .map((argument) => ({
        core_instance: index,
        core_module: consumer.module,
        import_module: argument.name,
        import_name: name,
        declared_by_module: declaresImport(
          component,
          consumer.module,
          argument.name,
          name,
        ),
      }));
  });

/** Core imports bound to a lowered function through inline-export core instances. */
const coreImportsBoundTo = (
  component: DecodedComponent,
  coreFunc: number,
): CoreBinding[] =>
  component.core_instances.flatMap((provider) => {
    const index = provider.index;
    if (provider.kind !== "inline-exports" || index === null) return [];
    return provider.exports
      .filter(
        (exported) =>
          exported.sort === "core func" && exported.index === coreFunc,
      )
      .flatMap((exported) => bindingsOf(component, index, exported.name));
  });

/**
 * Trace each canonical lift to the core export it wraps, and each lower to
 * its component source and the core imports it is bound to. Unknown index
 * spaces leave the corresponding facts null or empty rather than guessed.
 */
export const resolveCanonRelationships = (
  component: DecodedComponent,
  spaces: ComponentIndexSpaces,
): Pick<DecodedComponent, "lifts" | "lowers"> => {
  const lifts: DecodedComponent["lifts"] = [];
  const lowers: DecodedComponent["lowers"] = [];
  for (const [position, canon] of component.canons.entries()) {
    if (
      canon.kind === "lift" &&
      canon.core_func !== undefined &&
      canon.type !== undefined
    ) {
      const func = canon.defines.index;
      const coreOrigin = spaces.origin("core func", canon.core_func);
      let coreSource: DecodedComponent["lifts"][number]["core_source"] = null;
      if (coreOrigin?.kind === "alias-core-export") {
        const instance = spaces.origin("core instance", coreOrigin.instance);
        const module =
          instance?.kind === "core-instantiate" ? instance.module : null;
        coreSource = {
          core_instance: coreOrigin.instance,
          name: coreOrigin.name,
          core_module: module,
          declared_by_module: declaresExport(
            component,
            module,
            coreOrigin.name,
          ),
        };
      }
      lifts.push({
        canon: position,
        func,
        core_func: canon.core_func,
        type: canon.type,
        core_source: coreSource,
        exported_as:
          func === null
            ? []
            : component.exports
                .filter(
                  ({ target }) =>
                    target.sort === "func" &&
                    definingEntry(spaces, "func", target.index)?.index === func,
                )
                .map(({ name }) => name),
      });
    }
    if (canon.kind === "lower" && canon.func !== undefined) {
      const coreFunc = canon.defines.index;
      const defining = definingEntry(spaces, "func", canon.func);
      let source: DecodedComponent["lowers"][number]["component_source"] = null;
      if (defining?.origin.kind === "import")
        source = { kind: "import", name: defining.origin.name };
      else if (defining?.origin.kind === "alias-export") {
        const instance = definingEntry(
          spaces,
          "instance",
          defining.origin.instance,
        );
        source = {
          kind: "instance-export",
          instance: defining.origin.instance,
          name: defining.origin.name,
          instance_import:
            instance?.origin.kind === "import" ? instance.origin.name : null,
        };
      }
      lowers.push({
        canon: position,
        func: canon.func,
        core_func: coreFunc,
        component_source: source,
        satisfies:
          coreFunc === null ? [] : coreImportsBoundTo(component, coreFunc),
      });
    }
  }
  return { lifts, lowers };
};
