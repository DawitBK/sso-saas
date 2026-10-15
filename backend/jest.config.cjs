module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  forceExit: true,
  roots: ["<rootDir>/tests"],
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: "<rootDir>/tsconfig.json",
        diagnostics: {
          ignoreCodes: [151002],
        },
      },
    ],
  },
};
