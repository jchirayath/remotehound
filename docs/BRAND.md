# RemoteHound brand

The RemoteHound mascot is a friendly **beagle looking out of a browser window**, with a **signal** above the
window and a terminal prompt (`>_`) in its title bar. It is the same hound as MediaHound's (a sister
project by the same author): tan coat, white blaze and muzzle, long ears, a smile with its tongue out.
MediaHound frames it with a retro TV and headphones; RemoteHound swaps those for the things this product is
about: a browser window (sessions run in a tab) and a signal (the machine is somewhere else).

## Files

All of them are generated from one set of shapes by `node tools/brand/build.mjs` (run from the repo root).
Change the artwork there, not in the SVG files, so the files can't drift apart.

| File | Use |
|---|---|
| `web/ui/brand/mascot.svg` · `mascot-dark.svg` | Full mascot (window, beagle, signal). Sign-in page, empty states, 404, website hero. |
| `web/ui/brand/mark.svg` · `mark-dark.svg` | Beagle head under the signal arcs. App header / sidebar, loading screen. Both files are the same; the pair is kept so `app.css`'s theme switch stays uniform. |
| `web/ui/favicon.svg` | Browser tab icon (16 / 32 px): the head only, on a light outline. |
| `web/ui/favicon.ico` · `apple-touch-icon.png` | Bitmap copies for Safari (which ignores SVG favicons) and iOS home screens: the favicon at 16/32/48 px, and the mark on the light panel color at 180 px. Rendered from the SVGs by `node tools/brand/raster.mjs` (needs Chrome); re-run it after `build.mjs` and commit the output. |
| `docs/img/logo-light.svg` · `logo-dark.svg` | Mark + "Remote**Hound**" wordmark for the README and docs. |
| `website/img/*.svg` | Copies for the project website (written by the same script). |

The `-dark` mascot lifts the window frame and darkens the screen so the window keeps its shape on dark
surfaces; the beagle itself is the same in both. The UI picks the file in `app.css` (`--brand-mark`,
`--brand-mascot`) with the same rules as `tokens.css`, so it follows the theme controller, not just the
OS. Screens never inline SVG: use `mascot(state)` from `lib/ui.js`, or the `.brand__mark` class. States
are CSS on one file: `waiting` (a slow tilt, off under reduced motion) and `lost` (a held tilt, for 404).
An empty state shows the hound when its help-registry entry has `"mascot": "waiting"`.

## Construction

- Drawn on a 120 × 128 grid (mark: the head at 0.8 scale on 64 × 64; favicon: 0.4 on 32 × 32), symmetric
  about the vertical center. Flat fills only: no gradients, strokes only for the brows, mouth, signal arcs
  and the `>_` glyph, no raster, no fonts.
- Head: a round skull in the coat color; a white blaze running down from the crown that opens into a
  white muzzle; two long, darker ears hanging in front of the skull; round eyes with a highlight; curved
  brows; a soft rounded nose; a smile with a small tongue.
- Mascot: the head at 1.25 scale fills the screen of a rounded browser window (three title-bar dots, the
  first one tan, and a tan `>_` on the right). Two signal arcs and a dot sit above the window, where
  MediaHound's TV has its antennas.
- The mark drops the eye highlights, brows and tongue, enlarges the eyes and keeps the signal arcs, so it
  survives at 24–32 px. The favicon drops the arcs too.

## Colors

The portal palette is still blue and tan: the window frame is the brand blue, the signal and prompt are
the tan accent, and the beagle brings its own coat.

| Part | Light | Dark | Token |
|---|---|---|---|
| Window frame | `#24478A` | `#4A74BD` | `color.brand.700` / `color.brand.500` (the coat blue of the previous mascot) → `color.brand.primary` |
| Window screen | `#EEF3FB` | `#15203A` | — (artwork only) |
| Signal, `>_`, first dot | `#DDA45F` | `#DDA45F` | `color.tan.400` → `color.domain.brand.tan` (dark), `color.brand.accent` (dark) |
| Coat | `#D9822B` | `#D9822B` | — (artwork only; close to MediaHound's hound tan `#D7822F`) |
| Ears, "Hound" in the logo | `#B5651D` | `#B5651D` / `#E9A55A` (logo text) | — (artwork only) |
| Blaze, muzzle | `#FFFFFF` | `#FFFFFF` | — |
| Eyes, nose, brows, mouth | `#16232A` | `#16232A` | — (MediaHound's brand ink) |
| Tongue | `#F2654E` | `#F2654E` | — (MediaHound's tongue) |

Screen code never uses these hex values; it uses the semantic tokens (`--color-brand-*`,
`--color-domain-brand-*`). The SVG files are assets and carry their colors directly — if the palette
changes, change `tools/brand/build.mjs` and re-run it.

## Clear space and minimum size

- Clear space around the mark or mascot: at least the width of one ear on every side (about a quarter of
  the mark's width). Around the logo: the height of the "R".
- Minimum sizes: mark 20 px, full mascot 64 px (below that, use the mark), logo 120 px wide, favicon
  16 px.

## Do

- Use the provided files as they are, on `surface` colors, with the light or dark file matching the
  background.
- Let the mascot sit on a horizon (a bottom edge or rule) — that is how the sign-in page and empty states
  frame it.
- Pair it with plain, direct copy. The hound is the warmth; the words stay professional.

## Don't

- Recolor, stretch, rotate (beyond the CSS states), outline or add effects (shadows, glows, gradients)
  to the artwork.
- Put the light mascot on a dark background or the dark one on a light background.
- Add speech bubbles, props, costumes or expressions, or use the mascot to deliver error messages.
- Combine the mark with another logo, or use it to imply endorsement of a third-party product.

## License

The RemoteHound mascot, mark, favicon and logo are original artwork for this project, adapted from the
hound in MediaHound's logo, a sister project by the same author. They are released with the rest of the
repository under the [Apache License 2.0](../LICENSE). The Apache license does not grant trademark rights
(§6): forks should use their own name and mark.
