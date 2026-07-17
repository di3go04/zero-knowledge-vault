import "reflect-metadata";
import { container, injectable, inject } from "tsyringe";

export { injectable, inject, container };

export function initializeContainer() {
  return container;
}
