	google.load("visualization", "1", {packages:["corechart"]});
	google.setOnLoadCallback(loadData);

	function loadData(){
		$.when(
			$.ajax({
			    dataType: "json",
			    url: 'json/response_codes.json',
			    // data: {},
			    success: function(data, status, xhr) {
			      drawPieChart(data);
			    }
			}),
			$.ajax({
			    dataType: "json",
			    url: 'json/hits.json',
			    // data: {},
			    success: function(data, status, xhr) {
			      drawBarChart(data);
			    }
			}),
			$.ajax({
			    dataType: "json",
			    url: 'json/CCDF.json',
			    // data: {},
			    success: function(data, status, xhr) {
			      drawCCDFChart(data);
			    }
			})
		).then(setTimeout(function(){
				init_charts()
			}, 500)
		);
	}

	function init_charts(){
		show_response_codes()
	}

	function show_response_codes(){
		$(".ccdf").hide();
		$(".hits").hide();
		$(".response").fadeIn(1000);
	}

	function show_hits(){
		$(".ccdf").hide();
		$(".response").hide();
		$(".hits").fadeIn(1000);
	}

	function show_ccdf(){
		$(".response").hide();
		$(".hits").hide();
		$(".ccdf").fadeIn(1000);
	}

	function drawCCDFChart(datos) {
		//Domains
		var data = google.visualization.arrayToDataTable(datos);
		var options = {
		  title: 'CCDF',
		  hAxis: {
		  	logScale: true,
		  	title: 'Tiempo de Respuesta'
		  },
		  vAxis: {
		  	title: 'Probabilidad Acumulada'
		  }
		};
		var chart = new google.visualization.LineChart(document.getElementById('ccdf_div'));
		chart.draw(data, options);
	}

	function drawBarChart(datos) {

		//ADD TAG
		for(var k in datos){
			datos[k].unshift(['Códigos de Respuesta', 'Cantidad'])
		}

		//Domains
		var data = google.visualization.arrayToDataTable(datos['Domains']);
		var options = {
		  title: 'Domains',
		  fontSize: 12,
		  vAxis: {
		  	title: 'Dominios',
		  },
		  chartArea: {left:300, width:500},
		  legend: {
		  	position: 'none'
		  },
		  hAxis: {
		  	title: 'Cantidad',
		  	gridlines: {
          		count: 5,
          	}
		  }
		};
		var chart = new google.visualization.BarChart(document.getElementById('barchart_div_domains'));
		chart.draw(data, options);

		//IPs
		var data = google.visualization.arrayToDataTable(datos['IPs']);
		var options = {
		  title: 'IPs',
		  fontSize: 12,
		  vAxis: {
		  	title: 'IPs',
		  },
		  chartArea: {left:300, width:500},
		  legend: {
		  	position: 'none'
		  },
		  hAxis: {
		  	title: 'Cantidad',
		  	gridlines: {
          		count: 5,
          	}
		  }
		};
		var chart = new google.visualization.BarChart(document.getElementById('barchart_div_ips'));
		chart.draw(data, options);

		//URLs
		var data = google.visualization.arrayToDataTable(datos['URLs']);
		var options = {
		  title: 'URLs',
		  fontSize: 12,
		  vAxis: {
		  	title: 'URLs',
		  },
		  chartArea: {left:300, width:500},
		  legend: {
		  	position: 'none'
		  },
		  hAxis: {
		  	title: 'Cantidad',
		  	gridlines: {
          		count: 5,
          	}
		  }
		};
		var chart = new google.visualization.BarChart(document.getElementById('barchart_div_urls'));
		chart.draw(data, options);

	}

	function drawPieChart(datos) {

		//ADD TAG
		for(var k in datos){
			datos[k].unshift(['Códigos de Respuesta', 'Cantidad'])
		}

		var data = google.visualization.arrayToDataTable(datos['codes']);

		var options = {
		  title: 'Códigos de respuesta'
		};

		var chart = new google.visualization.PieChart(document.getElementById('chart_div'));
		chart.draw(data, options);

		google.visualization.events.addListener(chart, 'select', selectHandler);

		function selectHandler() {
			var selection = chart.getSelection();
			// console.log(selection);
			for (var i = 0; i < selection.length; i++) {
		    	var item = selection[i];
		   		//alert(item.row + " " + pieChartdata[item.row+1][0]  + " " + pieChartdata[item.row+1][1]);
		   		var codigo = datos['codes'][item.row+1][0]
		   		drawAuxPieChart(datos[codigo], codigo);
			}
		}
	}

	function drawAuxPieChart(datos, codigo) {
	    
	    
		$("#chart_div_aux").css('visibility', 'hidden');
	    var data = google.visualization.arrayToDataTable(datos);

	    var options = {
	      title: 'IPs para el código de respuesta: ' + codigo
	    };

	    var chart = new google.visualization.PieChart(document.getElementById('chart_div_aux'));
	    chart.draw(data, options);
		
	    $("#chart_div_aux").css('visibility', 'visible');
	    $("#chart_div_aux").css('background-color', 'red');
	    $("#chart_div_aux").hide();
	    $("#chart_div_aux").fadeIn(1500);
	  }

	