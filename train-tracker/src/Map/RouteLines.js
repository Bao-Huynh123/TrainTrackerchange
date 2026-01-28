import colormap from "colormap";
import { Polyline, Popup} from "react-leaflet";

/**
 * Component displaying routes as leaflet Polylines.
 * @component
 * @module RouteLines
 * @param {object[]} routes - The route location information.
 * @param {string} mapRoute - The currently selected route in search, to be displayed on the map.
 * @returns {JSX.Element} The route lines component.
 */
const RouteLines = ({routes, mapRoute}) =>{
    if (routes){
        let colors = colormap({
            colormap: 'plasma',
            nshades: routes.length,
            format: 'hex',
            alpha: 1
        });
        let routesToDisplay = routes.features;
        const name_map = new Map([
            ['Amtrak Cascades', 'Cascades'],
            ['Carolinian / Piedmont', 'Carolinian'],
            ['Downeaster', 'The Downeaster'],
            ['Hiawatha', 'Hiawathas'],
            ['Illinois Service', 'Illini (Illinois_Service)'],
            ['Keystone', 'Keystone Service'],
            ['Lincoln Service Missouri River Runner', 'Kansas City - St. Louis (Missouri River Runner)'],
            ['Missouri River Runner', 'Kansas City - St. Louis (Missouri River Runner)'],
            ['Michigan Services', 'Wolverines (Michigan_Services)'],
            ['Northeast Regional', 'Regional'],
            ['Silver Service / Palmetto', 'Palmetto'],
        ]);

        if (mapRoute){
            if (name_map.has(mapRoute)){
                routesToDisplay = routes.features.filter((feature) => feature.properties.name === name_map.get(mapRoute));
            }
            else{
                routesToDisplay = routes.features.filter((feature) => feature.properties.name === mapRoute)
            }
            
        }
        if (routesToDisplay){
            return (<div>
                {routesToDisplay.map((feature) => {
                    return(<Polyline positions={feature.geometry.coordinates} pathOptions={{ color: colors[feature.id-1], weight:'5'}} key={feature.properties.name}>
                        {<Popup>
                            {feature.properties.name}
                        </Popup>}
                    </Polyline>)
                })} 
            </div>)
        }     
    }
    else{
        return <div></div>
    }
}
export default RouteLines;