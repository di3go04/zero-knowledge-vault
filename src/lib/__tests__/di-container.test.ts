import { describe, it, expect } from "vitest";
import { container } from "../di-container";

describe("DI Container", () => {
  it("should be initialized", () => {
    expect(container).toBeDefined();
    expect(container.isRegistered).toBeDefined();
  });

  it("should resolve registered dependencies", () => {
    class TestService {
      greet() {
        return "hello";
      }
    }

    container.registerSingleton(TestService);
    const instance = container.resolve(TestService);
    expect(instance.greet()).toBe("hello");
  });
});
