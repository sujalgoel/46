declare module "ml-isolation-forest" {
  export class IsolationForest {
    constructor(options?: { nEstimators?: number; maxSamples?: number; contamination?: number });
    fit(data: number[][]): this;
    scores(data: number[][]): number[];
  }
}
