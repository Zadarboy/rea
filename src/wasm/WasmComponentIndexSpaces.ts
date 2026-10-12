import type { ComponentSort } from "../domain/wasm/wasmComponentTypes.js";

/** How an index-space entry was introduced; used to trace canonical relationships. */
export type IndexOrigin =
  | { readonly kind: "import"; readonly name: string }
  | { readonly kind: "export"; readonly of: number }
  | {
      readonly kind: "alias-export";
      readonly instance: number;
      readonly name: string;
    }
  | {
      readonly kind: "alias-core-export";
      readonly instance: number;
      readonly name: string;
    }
  | {
      readonly kind: "core-instantiate";
      readonly module: number;
      readonly args: readonly { name: string; instance: number }[];
    }
  | {
      readonly kind: "core-inline-exports";
      readonly exports: readonly {
        name: string;
        sort: ComponentSort;
        index: number;
      }[];
    }
  | { readonly kind: "canon"; readonly canon: number }
  | { readonly kind: "other" };

/** Index spaces of one component; a sort becomes unknown after an undecoded definition. */
export class ComponentIndexSpaces {
  readonly #spaces = new Map<ComponentSort, IndexOrigin[]>();
  readonly #unknown = new Set<ComponentSort>();
  #allUnknown = false;

  /** Append an entry; its index is null once the sort's count is unknown. */
  add(sort: ComponentSort, origin: IndexOrigin): number | null {
    const space = this.#spaces.get(sort) ?? [];
    this.#spaces.set(sort, space);
    space.push(origin);
    return this.#allUnknown || this.#unknown.has(sort)
      ? null
      : space.length - 1;
  }

  /** Origin at a known index, or undefined when it is unknown or absent. */
  origin(sort: ComponentSort, index: number): IndexOrigin | undefined {
    if (this.#allUnknown || this.#unknown.has(sort)) return undefined;
    return this.#spaces.get(sort)?.[index];
  }

  invalidate(sorts: readonly ComponentSort[] | "all"): void {
    if (sorts === "all") this.#allUnknown = true;
    else for (const sort of sorts) this.#unknown.add(sort);
  }
}
