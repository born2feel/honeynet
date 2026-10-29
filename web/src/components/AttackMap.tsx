import { useMemo, useState } from "react";
import { geoNaturalEarth1, geoPath, geoGraticule10 } from "d3-geo";
import { feature } from "topojson-client";
import type { FeatureCollection, Geometry } from "geojson";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import type { MapPoint, Sensor } from "../api";
import { flag, num } from "../format";

const W = 960;
const H = 470;

const projection = geoNaturalEarth1().fitExtent(
  [
    [4, 4],
    [W - 4, H - 4],
  ],
  { type: "Sphere" },
);
const path = geoPath(projection);

const topo = world as unknown as Topology<{ countries: GeometryCollection }>;
const countries = feature(topo, topo.objects.countries) as FeatureCollection<Geometry>;
const countryPaths = countries.features.map((f, i) => <path key={i} d={path(f) ?? ""} className="land" />);
const sphere = path({ type: "Sphere" }) ?? "";
const graticule = path(geoGraticule10()) ?? "";

export interface Ping {
  id: number;
  lat: number;
  lon: number;
  sensor: Sensor;
}

export function AttackMap({ points, pings }: { points: MapPoint[]; pings: Ping[] }) {
  const [hover, setHover] = useState<MapPoint | null>(null);
  const max = useMemo(() => Math.max(1, ...points.map((p) => p.attacks)), [points]);

  return (
    <div className="map-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} className="map" role="img" aria-label="World map of attack origins">
        <path d={sphere} className="sphere" />
        <path d={graticule} className="graticule" />
        <g>{countryPaths}</g>
        <g>
          {points.map((p) => {
            const xy = projection([p.lon, p.lat]);
            if (!xy) return null;
            const r = 2 + 14 * Math.sqrt(p.attacks / max);
            return (
              <circle
                key={`${p.lat},${p.lon}`}
                cx={xy[0]}
                cy={xy[1]}
                r={r}
                className="origin"
                onMouseEnter={() => setHover(p)}
                onMouseLeave={() => setHover(null)}
              />
            );
          })}
        </g>
        <g>
          {pings.map((p) => {
            const xy = projection([p.lon, p.lat]);
            if (!xy) return null;
            return (
              <g key={p.id} transform={`translate(${xy[0]},${xy[1]})`}>
                <circle r={4} className={`ping ping-${p.sensor}`} />
                <circle r={3} className={`ping-core ping-${p.sensor}`} />
              </g>
            );
          })}
        </g>
      </svg>
      {hover && (
        <div className="map-tip">
          <strong>
            {flag(hover.country_code)} {hover.city || hover.country_code}
          </strong>
          <span>
            {num(hover.attacks)} attacks · {num(hover.ips)} IPs
          </span>
        </div>
      )}
      {points.length === 0 && (
        <div className="map-empty">
          No geolocated attacks yet. Set <code>HONEYNET_GEOIP_DB</code> to a GeoLite2-City database.
        </div>
      )}
    </div>
  );
}
