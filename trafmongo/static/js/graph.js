var width = 960,
    height = 500;

var color = d3.scale.category20();

var force = d3.layout.force()
    .charge(-120)
    .linkDistance(30)
    .size([width, height]);

$(function() {
    var svg = d3.select("#graph").append("svg:svg")
        .attr("width", width)
        .attr("height", height);

    d3.json("/static/test.json", function(error, graph) {
        force
            .nodes(graph.nodes)
            .links(graph.links)
            .start();

        var link = svg.selectAll("line.link")
            .data(graph.links)
          .enter().append("line")
            .attr("class", "link")
            .style("stroke-width", function(d) { return Math.sqrt(d.value); });

        var node = svg.selectAll("rect.node")
            .data(graph.nodes)
          .enter().append("rect")
            .attr("class", "node")
	    .attr("width", "40")
	    .attr("height", "40")
            .style("fill", function(d) { return "blue"; })
            .call(force.drag);
    
        node.append("title")
            .text(function(d) { return d.name; });
    
        force.on("tick", function() {
            link.attr("x1", function(d) { return d.source.x; })
                .attr("y1", function(d) { return d.source.y; })
                .attr("x2", function(d) { return d.target.x; })
                .attr("y2", function(d) { return d.target.y; });
    
            node.attr("x", function(d) { return d.x-20; })
                .attr("y", function(d) { return d.y-20; });
        });
    });
});
